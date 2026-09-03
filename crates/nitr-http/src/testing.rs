// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! In-process testing: dispatch requests through the full protection /
//! router / middleware / handler path without binding a socket. This is
//! the foundation of `nitr test` and of Rust-level integration tests.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, Uri};
use tokio::sync::Semaphore;

use crate::handler;
use crate::protect::Protection;
use crate::request::LuaRequest;
use crate::server::current_pool;
use nitr_core::{Error, Result, RuntimePool};

/// An in-process client for a built [`Server`](crate::Server); obtained
/// via [`Server::test_client()`](crate::Server::test_client).
#[derive(Clone)]
pub struct TestClient {
    pool: Arc<RwLock<Arc<RuntimePool>>>,
    streams: Arc<Semaphore>,
    protection: Arc<Protection>,
}

/// A fully collected response from [`TestClient::request`].
#[derive(Debug)]
pub struct TestResponse {
    /// HTTP status code.
    pub status: u16,
    /// Header pairs in response order (repeated names appear repeatedly).
    pub headers: Vec<(String, String)>,
    /// The collected response body.
    pub body: Bytes,
}

impl TestClient {
    pub(crate) fn new(
        pool: Arc<RwLock<Arc<RuntimePool>>>,
        streams: Arc<Semaphore>,
        protection: Arc<Protection>,
    ) -> Self {
        Self {
            pool,
            streams,
            protection,
        }
    }

    /// Performs one request through the real dispatch path and collects
    /// the response (streaming bodies included).
    pub async fn request(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> Result<TestResponse> {
        let method: Method = method
            .to_uppercase()
            .parse()
            .map_err(|_| Error::Config(format!("invalid test request method `{method}`")))?;
        let uri: Uri = path_and_query
            .parse()
            .map_err(|_| Error::Config(format!("invalid test request path `{path_and_query}`")))?;

        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let req = builder.body(
            Full::new(body.unwrap_or_default())
                .map_err(|never| match never {})
                .boxed(),
        )?;

        let id = self.protection.request_id_for_parts(req.headers());
        let peer: SocketAddr = ([127, 0, 0, 1], 0).into();
        let req = LuaRequest {
            peer_addr: peer,
            req,
            params: Vec::new(),
            id: id.into(),
            // Replaced with the configured bounds by the handler.
            limits: Default::default(),
            cached_form: None,
            body_limit: u64::MAX,
        };

        let pool = current_pool(&self.pool);
        let resp =
            handler::handle(&pool, req, self.streams.clone(), self.protection.clone()).await?;

        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let body = match resp.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            // The response body error type is Infallible.
            Err(never) => match never {},
        };
        Ok(TestResponse {
            status,
            headers,
            body,
        })
    }
}

impl TestResponse {
    /// The first value of a (case-insensitive) header, if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}
