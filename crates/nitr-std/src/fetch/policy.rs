// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Outbound-request policy for the `fetch` builtin: SSRF protection.
//!
//! Once scripts can `fetch(...)`, the server is a potential SSRF primitive,
//! so by default requests to loopback, private, link-local, and other
//! special-purpose addresses are refused — the target host is resolved and
//! *all* of its addresses checked, and every redirect hop is re-validated
//! against the same policy.

use std::net::IpAddr;
use std::time::Duration;

use mlua::ExternalResult as _;
use reqwest::Url;

use crate::config::FetchOptions;

/// The parts of the policy that decide which addresses may be connected to.
///
/// Split out because the DNS resolver needs exactly this and nothing else,
/// and because it is what the client is keyed on: two configurations that
/// agree here can share a connection pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ConnectPolicy {
    pub(crate) allow_private_networks: bool,
    pub(crate) connect_timeout: Duration,
    pub(crate) timeout: Duration,
    pub(crate) pool_max_idle_per_host: usize,
    pub(crate) proxy: Option<String>,
    pub(crate) no_proxy: bool,
}

impl FetchOptions {
    pub(crate) fn connect_policy(&self) -> ConnectPolicy {
        ConnectPolicy {
            allow_private_networks: self.allow_private_networks,
            connect_timeout: self.connect_timeout,
            timeout: self.timeout,
            pool_max_idle_per_host: self.pool_max_idle_per_host,
            proxy: self.proxy.clone(),
            no_proxy: self.no_proxy,
        }
    }
}

/// A DNS resolver that refuses to hand the connector an address the policy
/// forbids.
///
/// This is what closes the rebinding hole. The old flow resolved a name,
/// checked the addresses, and then passed the *name* to the connector,
/// which resolved it again — so a malicious DNS server could answer
/// `93.184.216.34` to the check and `169.254.169.254` to the connect. Here
/// the filtering happens inside the single resolution the connector
/// actually uses, so the checked value and the used value are the same one.
#[derive(Debug)]
pub(crate) struct GuardedResolver {
    allow_private_networks: bool,
}

impl GuardedResolver {
    pub(crate) fn new(allow_private_networks: bool) -> Self {
        Self {
            allow_private_networks,
        }
    }
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_private = self.allow_private_networks;
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0: the connector substitutes the real one. Only the
            // address matters for the policy.
            let resolved: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|err| -> BoxError { Box::new(err) })?
                .collect();
            if resolved.is_empty() {
                return Err(no_address(&host));
            }
            let allowed: Vec<std::net::SocketAddr> = resolved
                .into_iter()
                .filter(|addr| allow_private || !is_forbidden_ip(addr.ip()))
                .collect();
            if allowed.is_empty() {
                return Err(forbidden(&host));
            }
            Ok(Box::new(allowed.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn no_address(host: &str) -> BoxError {
    format!("fetch host `{host}` did not resolve to any address").into()
}

fn forbidden(host: &str) -> BoxError {
    format!(
        "fetch host `{host}` resolves to a private or local address \
         (set fetch.allow_private_networks to permit this)"
    )
    .into()
}

/// Validates one request URL against the policy. Called for the initial
/// URL and again for every redirect hop, so redirects cannot cross the
/// trust boundary.
pub(crate) async fn check_url(url: &Url, opts: &FetchOptions) -> mlua::Result<()> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(mlua::Error::RuntimeError(format!(
            "fetch only supports http/https URLs, got `{url}`"
        )));
    }
    let Some(host) = url.host() else {
        return Err(mlua::Error::RuntimeError(format!(
            "fetch URL `{url}` has no host"
        )));
    };

    if let Some(allowed) = &opts.allowed_hosts {
        let name = url.host_str().unwrap_or_default();
        if !allowed.iter().any(|a| a.eq_ignore_ascii_case(name)) {
            return Err(mlua::Error::RuntimeError(format!(
                "fetch host `{name}` is not in fetch.allowed_hosts"
            )));
        }
    }

    if opts.allow_private_networks {
        return Ok(());
    }

    // A first look, so a forbidden target fails with a clear message
    // rather than a connector error. It is not the security boundary:
    // [`GuardedResolver`] filters the resolution the connector actually
    // uses, which is what makes rebinding between the two impossible.
    let ips: Vec<IpAddr> = match host {
        url::Host::Ipv4(ip) => vec![ip.into()],
        url::Host::Ipv6(ip) => vec![ip.into()],
        url::Host::Domain(domain) => {
            let port = url.port_or_known_default().unwrap_or(80);
            tokio::net::lookup_host((domain, port))
                .await
                .into_lua_err()?
                .map(|addr| addr.ip())
                .collect()
        }
    };
    if ips.is_empty() {
        return Err(mlua::Error::RuntimeError(format!(
            "fetch host `{}` did not resolve to any address",
            url.host_str().unwrap_or_default()
        )));
    }
    if ips.iter().any(|ip| is_forbidden_ip(*ip)) {
        return Err(mlua::Error::RuntimeError(format!(
            "fetch host `{}` resolves to a private or local address \
             (set fetch.allow_private_networks to permit this)",
            url.host_str().unwrap_or_default()
        )));
    }
    Ok(())
}

/// Special-purpose address ranges refused unless private networks are
/// explicitly allowed: loopback, RFC1918, link-local (including cloud
/// metadata endpoints), CGNAT, unspecified, broadcast, and their IPv6
/// counterparts (ULA, link-local, v4-mapped forms).
fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // CGNAT 100.64.0.0/10
                || (octets[0] == 100 && (64..128).contains(&octets[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique-local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.to_ipv4_mapped().is_some_and(|v4| is_forbidden_ip(v4.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip literal")
    }

    #[test]
    fn special_purpose_addresses_are_forbidden() {
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_forbidden_ip(ip(bad)), "{bad} must be forbidden");
        }
        for good in ["93.184.216.34", "1.1.1.1", "2606:4700::1111"] {
            assert!(!is_forbidden_ip(ip(good)), "{good} must be allowed");
        }
    }

    /// The resolver is the actual boundary, not `check_url`: it filters the
    /// single resolution the connector uses, so there is no second lookup
    /// for a malicious DNS server to answer differently.
    #[tokio::test]
    async fn the_resolver_refuses_to_hand_over_a_forbidden_address() {
        use reqwest::dns::Resolve as _;

        let guarded = GuardedResolver::new(false);
        let name: reqwest::dns::Name = "localhost".parse().expect("name");
        let err = guarded
            .resolve(name)
            .await
            .err()
            .expect("localhost resolves to loopback and must be refused");
        assert!(err.to_string().contains("private or local"), "{err}");

        // The same name is fine once private networks are allowed, which
        // proves the refusal came from the policy and not from resolution.
        let open = GuardedResolver::new(true);
        let name: reqwest::dns::Name = "localhost".parse().expect("name");
        let addrs = open.resolve(name).await.expect("allowed");
        assert!(addrs.count() > 0);
    }

    #[tokio::test]
    async fn policy_checks_urls() {
        // Each refusal is pinned to its *reason*: a bare `is_err()` here
        // would also pass when the check failed for something unrelated
        // to the policy being tested.
        let default = FetchOptions::default();
        let url: Url = "http://127.0.0.1:8080/x".parse().expect("url");
        let err = check_url(&url, &default)
            .await
            .expect_err("loopback under the default policy");
        assert!(err.to_string().contains("private or local"), "got: {err}");

        let open = FetchOptions {
            allow_private_networks: true,
            ..Default::default()
        };
        check_url(&url, &open)
            .await
            .expect("loopback once private networks are allowed");

        // Non-http schemes are always refused, even under the open policy.
        let ftp: Url = "ftp://example.com/x".parse().expect("url");
        let err = check_url(&ftp, &open).await.expect_err("non-http scheme");
        assert!(err.to_string().contains("http/https"), "got: {err}");

        // The allow-list applies even with private networks allowed, and
        // the refusal names the setting to change.
        let listed = FetchOptions {
            allowed_hosts: Some(vec!["api.example.com".into()]),
            allow_private_networks: true,
            ..Default::default()
        };
        let other: Url = "http://evil.example.com/".parse().expect("url");
        let err = check_url(&other, &listed).await.expect_err("unlisted host");
        assert!(err.to_string().contains("allowed_hosts"), "got: {err}");
        // Host matching is case-insensitive, per DNS.
        let ok: Url = "http://API.example.com/".parse().expect("url");
        check_url(&ok, &listed)
            .await
            .expect("listed host, any case");

        // A forbidden *IP literal* is refused without any resolution — the
        // metadata-endpoint shape (`169.254.169.254`) must never depend on
        // what the host's resolver does.
        for literal in [
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/x",
            "http://10.0.0.7/x",
        ] {
            let url: Url = literal.parse().expect("url");
            let err = check_url(&url, &default)
                .await
                .expect_err("forbidden IP literal");
            assert!(
                err.to_string().contains("private or local"),
                "{literal}: {err}"
            );
        }
    }
}
