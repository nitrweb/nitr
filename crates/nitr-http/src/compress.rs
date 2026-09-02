// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Response compression: `Accept-Encoding` negotiation, precompressed
//! sidecar lookup for static files, and on-the-fly brotli/gzip.
//!
//! Two independent mechanisms, in preference order:
//!
//! 1. **Sidecars.** `app.js.br` next to `app.js` was compressed once at
//!    build time — best ratio, zero runtime CPU. Always used when present,
//!    regardless of the `[compression]` section.
//! 2. **On-the-fly**, for dynamic responses and static files without a
//!    sidecar. Off by default, because it trades the server's CPU for
//!    bandwidth and that should be a decision rather than a surprise.

#[cfg(feature = "compression")]
use std::convert::Infallible;
#[cfg(feature = "compression")]
use std::io::Write as _;
#[cfg(feature = "compression")]
use std::pin::Pin;
#[cfg(feature = "compression")]
use std::task::{Context, Poll};

#[cfg(feature = "compression")]
use http_body_util::BodyExt as _;
#[cfg(feature = "compression")]
use http_body_util::combinators::BoxBody;
#[cfg(feature = "compression")]
use hyper::StatusCode;
#[cfg(feature = "compression")]
use hyper::body::{Body, Bytes, Frame, SizeHint};
use hyper::header::HeaderValue;
#[cfg(feature = "compression")]
use hyper::header::{self};

use crate::config::CompressionConfig;
use crate::handler::HttpResponse;

/// A content coding Nitr can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Brotli (`br`).
    Brotli,
    /// gzip.
    Gzip,
}

impl Encoding {
    /// The `Content-Encoding` token.
    pub fn token(self) -> &'static str {
        match self {
            Encoding::Brotli => "br",
            Encoding::Gzip => "gzip",
        }
    }

    /// The file extension of a precompressed sidecar.
    pub(crate) fn extension(self) -> &'static str {
        match self {
            Encoding::Brotli => "br",
            Encoding::Gzip => "gz",
        }
    }

    /// The coding a request token names, if Nitr can produce it.
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "br" => Some(Encoding::Brotli),
            "gzip" => Some(Encoding::Gzip),
            _ => None,
        }
    }
}

/// The compiled `[compression]` policy plus the negotiation machinery,
/// which is needed for sidecars even when on-the-fly compression is off.
#[derive(Debug)]
pub struct Compression {
    /// Offered algorithms in server-preference order.
    algorithms: Vec<Encoding>,
    #[cfg(feature = "compression")]
    enabled: bool,
    #[cfg(feature = "compression")]
    min_size: u64,
    /// Compressible content types; an entry ending in `*` matches a prefix.
    #[cfg(feature = "compression")]
    types: Vec<String>,
}

/// Content types that are already compressed. Running them through gzip
/// spends CPU to make the payload very slightly larger.
#[cfg(feature = "compression")]
const INCOMPRESSIBLE: &[&str] = &[
    "image/",
    "video/",
    "audio/",
    "font/woff",
    "application/zip",
    "application/gzip",
    "application/x-brotli",
    "application/wasm",
];

impl Compression {
    pub(crate) fn new(cfg: &CompressionConfig) -> Self {
        Self {
            algorithms: cfg
                .algorithms
                .iter()
                .filter_map(|name| Encoding::from_token(name))
                .collect(),
            #[cfg(feature = "compression")]
            enabled: cfg.enabled,
            #[cfg(feature = "compression")]
            min_size: cfg.min_size,
            #[cfg(feature = "compression")]
            types: cfg.types.iter().map(|t| t.to_ascii_lowercase()).collect(),
        }
    }

    /// A negotiator offering exactly `algorithms`, so the fuzz target can
    /// drive the real [`Compression::negotiate`] instead of re-spelling its
    /// predicate — a copy of the rule cannot catch a change to the rule.
    ///
    /// The remaining fields belong to the compression path and are left
    /// inert: `negotiate` deliberately reads only the offered list, ignoring
    /// `enabled` so sidecar lookup still works with on-the-fly compression
    /// switched off.
    #[doc(hidden)]
    pub fn negotiator_for_fuzzing(algorithms: Vec<Encoding>) -> Self {
        Self {
            algorithms,
            #[cfg(feature = "compression")]
            enabled: false,
            #[cfg(feature = "compression")]
            min_size: 0,
            #[cfg(feature = "compression")]
            types: Vec::new(),
        }
    }

    /// The best encoding for this request, considering only what the server
    /// offers. Used for sidecar lookup, so it ignores `enabled`.
    pub fn negotiate(&self, accept_encoding: Option<&HeaderValue>) -> Option<Encoding> {
        let accepted = parse_accept_encoding(accept_encoding?.to_str().ok()?);
        // Server preference order wins among everything the client accepts,
        // so the `algorithms` list is a real knob rather than advisory.
        self.algorithms
            .iter()
            .copied()
            .find(|enc| accepted.iter().any(|(token, q)| *q > 0.0 && token == enc))
    }

    /// Compresses a response in place when the policy allows it.
    ///
    /// Returns the response untouched whenever compression would be wrong
    /// or pointless: disabled, already encoded, a status with no body, a
    /// partial response (the range was computed against the identity
    /// bytes), an incompressible type, or a body known to be too small.
    #[cfg(not(feature = "compression"))]
    pub(crate) fn apply(&self, resp: HttpResponse, _encoding: Option<Encoding>) -> HttpResponse {
        // Built without an encoder. Sidecar selection still works, since
        // serving an already-compressed file needs no compression code.
        resp
    }

    #[cfg(feature = "compression")]
    pub(crate) fn apply(&self, mut resp: HttpResponse, encoding: Option<Encoding>) -> HttpResponse {
        let Some(encoding) = encoding.filter(|_| self.enabled) else {
            return resp;
        };
        if !self.should_compress(&resp) {
            return resp;
        }

        // The identity length no longer describes the body, and the range
        // machinery must not be pointed at compressed bytes.
        let headers = resp.headers_mut();
        headers.remove(header::CONTENT_LENGTH);
        headers.remove(header::ACCEPT_RANGES);
        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static(encoding.token()),
        );
        // Without this, a shared cache hands compressed bytes to a client
        // that never asked for them.
        crate::cors::append_vary(headers, "accept-encoding");
        // An ETag identifies a representation, and this is a different one.
        if let Some(etag) = headers.get(header::ETAG).and_then(|v| v.to_str().ok()) {
            let weakened = weaken_etag(etag, encoding.token());
            if let Ok(value) = HeaderValue::from_str(&weakened) {
                headers.insert(header::ETAG, value);
            }
        }

        let (parts, body) = resp.into_parts();
        let body = CompressedBody::new(body, encoding).boxed();
        HttpResponse::from_parts(parts, body)
    }

    #[cfg(feature = "compression")]
    fn should_compress(&self, resp: &HttpResponse) -> bool {
        let status = resp.status();
        if status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED
            || status == StatusCode::PARTIAL_CONTENT
            || status.is_informational()
        {
            return false;
        }
        let headers = resp.headers();
        if headers.contains_key(header::CONTENT_ENCODING) {
            return false;
        }
        // `no-transform` is the application saying the bytes are the
        // representation — a signed payload, a byte-exact download.
        if headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|directive| directive.trim().eq_ignore_ascii_case("no-transform"))
        {
            return false;
        }
        // A known-small body is not worth a compressor. An unknown length
        // (a stream) is compressed: refusing would exclude exactly the
        // responses where compression pays best. The declared length is
        // consulted before the body's own hint: a `HEAD` answered from
        // the static path carries the file's `Content-Length` over an
        // empty body, and it must reach the same decision as the `GET`
        // it describes.
        let declared = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if let Some(len) = declared.or_else(|| resp.body().size_hint().exact())
            && len < self.min_size
        {
            return false;
        }
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if content_type.is_empty() || INCOMPRESSIBLE.iter().any(|p| content_type.starts_with(p)) {
            return false;
        }
        self.types
            .iter()
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(prefix) => content_type.starts_with(prefix),
                None => *pattern == content_type,
            })
    }
}

/// The weak validator for an encoded representation: `"abc"` under gzip
/// becomes `W/"abc-gzip"` — a well-formed entity-tag (the suffix stays
/// inside the quotes), and the shape `crate::request::is_fresh` knows to
/// map back to the identity tag on the next conditional request.
#[cfg(feature = "compression")]
pub(crate) fn weaken_etag(etag: &str, token: &str) -> String {
    let strong = etag.trim_start_matches("W/");
    match strong.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        Some(inner) => format!("W/\"{inner}-{token}\""),
        None => format!("W/\"{}-{token}\"", strong.trim_matches('"')),
    }
}

/// Parses `Accept-Encoding` into (encoding, q-value) pairs, keeping only
/// codings we can produce.
pub fn parse_accept_encoding(value: &str) -> Vec<(Encoding, f32)> {
    value
        .split(',')
        .filter_map(|entry| {
            let mut parts = entry.split(';');
            let token = parts.next()?.trim().to_ascii_lowercase();
            let encoding = Encoding::from_token(&token)?;
            let q = parts
                .find_map(|p| p.trim().strip_prefix("q=")?.parse::<f32>().ok())
                .unwrap_or(1.0);
            Some((encoding, q))
        })
        .collect()
}

#[cfg(feature = "compression")]
mod encoder {
    use super::*;

    /// A body that compresses each frame as it passes through.
    ///
    /// The compressors are synchronous, which is right here: the bytes are
    /// already in memory and compressing them is pure CPU, so there is nothing
    /// to await. Each frame is flushed so a streaming response still reaches
    /// the client incrementally — that costs a little ratio, and buffering
    /// instead would defeat the point of streaming.
    pub(super) struct CompressedBody {
        inner: BoxBody<Bytes, Infallible>,
        /// Taken by `finish`, which consumes the encoder to terminate the
        /// stream; `None` also marks the body as complete.
        encoder: Option<Encoder>,
    }

    pub(super) enum Encoder {
        Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
        Gzip(Box<flate2::write::GzEncoder<Vec<u8>>>),
    }

    impl CompressedBody {
        pub(super) fn new(inner: BoxBody<Bytes, Infallible>, encoding: Encoding) -> Self {
            let encoder = match encoding {
                // Quality 4 is the usual server-side pick: most of the ratio of
                // the higher levels for a fraction of the CPU. lgwin 22 is the
                // brotli default window.
                Encoding::Brotli => Encoder::Brotli(Box::new(brotli::CompressorWriter::new(
                    Vec::new(),
                    32 * 1024,
                    4,
                    22,
                ))),
                Encoding::Gzip => Encoder::Gzip(Box::new(flate2::write::GzEncoder::new(
                    Vec::new(),
                    flate2::Compression::fast(),
                ))),
            };
            Self {
                inner,
                encoder: Some(encoder),
            }
        }

        /// Compresses `data` and returns whatever the encoder is willing to
        /// release now (possibly nothing, when it is still filling its window).
        fn write(&mut self, data: &[u8]) -> std::io::Result<Bytes> {
            let Some(encoder) = self.encoder.as_mut() else {
                return Ok(Bytes::new());
            };
            match encoder {
                Encoder::Brotli(w) => {
                    w.write_all(data)?;
                    w.flush()?;
                    Ok(Bytes::from(std::mem::take(w.get_mut())))
                }
                Encoder::Gzip(w) => {
                    w.write_all(data)?;
                    w.flush()?;
                    Ok(Bytes::from(std::mem::take(w.get_mut())))
                }
            }
        }

        /// Terminates the stream, returning the compressor's trailing bytes.
        ///
        /// Both encoders need to be *consumed* to emit their end-of-stream
        /// marker: a plain flush ends a block, not the stream, and a decoder
        /// handed the result reports an unexpected EOF.
        fn finish(&mut self) -> std::io::Result<Bytes> {
            match self.encoder.take() {
                None => Ok(Bytes::new()),
                Some(Encoder::Brotli(w)) => Ok(Bytes::from(w.into_inner())),
                Some(Encoder::Gzip(w)) => Ok(Bytes::from(w.finish()?)),
            }
        }
    }

    impl Body for CompressedBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<std::result::Result<Frame<Bytes>, Infallible>>> {
            // `BoxBody` is a pinned box, so the wrapper is `Unpin`.
            let this = self.get_mut();
            loop {
                if this.encoder.is_none() {
                    return Poll::Ready(None);
                }
                match Pin::new(&mut this.inner).poll_frame(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(frame))) => {
                        let Some(data) = frame.data_ref() else {
                            // Trailers pass through untouched.
                            return Poll::Ready(Some(Ok(frame)));
                        };
                        match this.write(data) {
                            // The encoder buffered everything; ask for more
                            // rather than emitting a zero-length frame.
                            Ok(out) if out.is_empty() => continue,
                            Ok(out) => return Poll::Ready(Some(Ok(Frame::data(out)))),
                            Err(err) => {
                                // The body type is infallible, so the only
                                // honest option is to end the stream; the
                                // client sees a truncated response.
                                tracing::error!("response compression failed: {err}");
                                this.encoder = None;
                                return Poll::Ready(None);
                            }
                        }
                    }
                    Poll::Ready(Some(Err(never))) => match never {},
                    Poll::Ready(None) => {
                        return match this.finish() {
                            Ok(tail) if tail.is_empty() => Poll::Ready(None),
                            Ok(tail) => Poll::Ready(Some(Ok(Frame::data(tail)))),
                            Err(err) => {
                                tracing::error!("response compression failed to finish: {err}");
                                Poll::Ready(None)
                            }
                        };
                    }
                }
            }
        }

        fn size_hint(&self) -> SizeHint {
            // Compression makes the identity length meaningless, and an
            // inherited exact hint would contradict the bytes actually sent.
            SizeHint::default()
        }
    }
}

#[cfg(feature = "compression")]
use encoder::CompressedBody;

#[cfg(all(test, feature = "compression"))]
mod tests {
    use super::*;
    use http_body_util::Full;

    fn policy(enabled: bool) -> Compression {
        Compression::new(&CompressionConfig {
            enabled,
            ..Default::default()
        })
    }

    fn response(status: StatusCode, content_type: &str, body: &'static [u8]) -> HttpResponse {
        hyper::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, body.len())
            .body(Full::new(Bytes::from_static(body)).boxed())
            .expect("response")
    }

    async fn collect(resp: HttpResponse) -> Vec<u8> {
        resp.into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec()
    }

    const BIG_JSON: &[u8] = &[b'{'; 4096];

    #[test]
    fn negotiation_follows_server_preference() {
        let p = policy(true);
        let both = HeaderValue::from_static("gzip, br");
        assert_eq!(p.negotiate(Some(&both)), Some(Encoding::Brotli));

        let gzip_only = HeaderValue::from_static("gzip");
        assert_eq!(p.negotiate(Some(&gzip_only)), Some(Encoding::Gzip));

        // A zero q-value is a refusal, not a preference.
        let refused = HeaderValue::from_static("br;q=0, gzip;q=0");
        assert_eq!(p.negotiate(Some(&refused)), None);

        assert_eq!(p.negotiate(None), None);
        let unknown = HeaderValue::from_static("zstd");
        assert_eq!(p.negotiate(Some(&unknown)), None);
    }

    #[tokio::test]
    async fn gzip_round_trips_and_sets_the_headers() {
        use std::io::Read as _;
        let p = policy(true);
        let resp = p.apply(
            response(StatusCode::OK, "application/json", BIG_JSON),
            Some(Encoding::Gzip),
        );
        assert_eq!(resp.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(resp.headers()[header::VARY], "accept-encoding");
        // The identity length must not survive: it describes other bytes.
        assert!(!resp.headers().contains_key(header::CONTENT_LENGTH));

        let compressed = collect(resp).await;
        assert!(
            compressed.len() < BIG_JSON.len(),
            "compression must shrink it"
        );
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&compressed[..])
            .read_to_end(&mut out)
            .expect("decode");
        assert_eq!(out, BIG_JSON);
    }

    #[tokio::test]
    async fn brotli_round_trips() {
        let p = policy(true);
        let resp = p.apply(
            response(StatusCode::OK, "text/html", BIG_JSON),
            Some(Encoding::Brotli),
        );
        assert_eq!(resp.headers()[header::CONTENT_ENCODING], "br");
        let compressed = collect(resp).await;
        let mut out = Vec::new();
        brotli::BrotliDecompress(&mut &compressed[..], &mut out).expect("decode");
        assert_eq!(out, BIG_JSON);
    }

    #[tokio::test]
    async fn the_untouched_cases_stay_untouched() {
        let p = policy(true);
        let cases: Vec<(&str, HttpResponse)> = vec![
            (
                "small body",
                response(StatusCode::OK, "text/plain", b"tiny"),
            ),
            (
                "incompressible type",
                response(StatusCode::OK, "image/png", BIG_JSON),
            ),
            (
                "unlisted type",
                response(StatusCode::OK, "application/octet-stream", BIG_JSON),
            ),
            (
                "partial content",
                response(StatusCode::PARTIAL_CONTENT, "text/plain", BIG_JSON),
            ),
            (
                "not modified",
                response(StatusCode::NOT_MODIFIED, "text/plain", BIG_JSON),
            ),
        ];
        for (what, resp) in cases {
            let out = p.apply(resp, Some(Encoding::Gzip));
            assert!(
                !out.headers().contains_key(header::CONTENT_ENCODING),
                "{what} must not be compressed"
            );
        }

        // And nothing happens at all while the section is disabled.
        let off = policy(false);
        let out = off.apply(
            response(StatusCode::OK, "application/json", BIG_JSON),
            Some(Encoding::Gzip),
        );
        assert!(!out.headers().contains_key(header::CONTENT_ENCODING));
    }

    #[tokio::test]
    async fn an_already_encoded_response_is_left_alone() {
        let p = policy(true);
        let mut resp = response(StatusCode::OK, "application/json", BIG_JSON);
        resp.headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        let out = p.apply(resp, Some(Encoding::Gzip));
        assert_eq!(out.headers()[header::CONTENT_ENCODING], "br");
    }

    #[tokio::test]
    async fn compressing_weakens_the_etag() {
        let p = policy(true);
        let mut resp = response(StatusCode::OK, "application/json", BIG_JSON);
        resp.headers_mut()
            .insert(header::ETAG, HeaderValue::from_static("\"abc\""));
        let out = p.apply(resp, Some(Encoding::Gzip));
        assert_eq!(out.headers()[header::ETAG], "W/\"abc-gzip\"");
    }
}
