#![forbid(unsafe_code)]

use std::{error::Error, fmt, net::IpAddr, str::FromStr};

const MAX_URL_LEN: usize = 2_048;
const MAX_PROXY_URL_LEN: usize = 512;
const DEFAULT_MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkPolicy {
    pub inbound_listener: bool,
    pub port_forwarding: bool,
    pub upnp: bool,
    pub nat_pmp: bool,
}

impl NetworkPolicy {
    pub const fn outbound_only(self) -> bool {
        !self.inbound_listener && !self.port_forwarding && !self.upnp && !self.nat_pmp
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrivacyRoute {
    #[default]
    Direct,
    Proxy,
    Tor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointClass {
    Remote,
    Loopback,
    Onion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub max_response_bytes: u64,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 15,
            request_timeout_secs: 45,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

impl RequestLimits {
    pub fn validate(self) -> Result<(), NetworkError> {
        if !(1..=60).contains(&self.connect_timeout_secs)
            || !(1..=300).contains(&self.request_timeout_secs)
            || self.request_timeout_secs < self.connect_timeout_secs
            || !(1_024..=64 * 1024 * 1024).contains(&self.max_response_bytes)
        {
            return Err(NetworkError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetadataPolicy {
    pub send_referer: bool,
    pub persist_cookies: bool,
    pub cache_responses: bool,
    pub include_device_identifier: bool,
}


impl MetadataPolicy {
    pub const fn minimized(self) -> bool {
        !self.send_referer
            && !self.persist_cookies
            && !self.cache_responses
            && !self.include_device_identifier
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint(String);

impl ProxyEndpoint {
    pub fn new(value: &str, route: PrivacyRoute) -> Result<Self, NetworkError> {
        if value.is_empty()
            || value.len() > MAX_PROXY_URL_LEN
            || value.chars().any(char::is_control)
            || value.contains('#')
            || value.contains('@')
        {
            return Err(NetworkError::InvalidProxy);
        }

        let (scheme, authority) = split_scheme_authority(value)?;
        let host = authority_host(authority)?;

        match route {
            PrivacyRoute::Direct => return Err(NetworkError::UnexpectedProxy),
            PrivacyRoute::Proxy => {
                if !matches!(scheme, "https" | "socks5h") {
                    return Err(NetworkError::InvalidProxy);
                }
            }
            PrivacyRoute::Tor => {
                if scheme != "socks5h" || !is_loopback_host(host) {
                    return Err(NetworkError::InvalidTorProxy);
                }
            }
        }

        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTarget {
    url: String,
    class: EndpointClass,
}

impl OutboundTarget {
    pub fn new(
        value: &str,
        route: PrivacyRoute,
        allow_loopback_plaintext: bool,
    ) -> Result<Self, NetworkError> {
        if value.is_empty()
            || value.len() > MAX_URL_LEN
            || value.chars().any(char::is_control)
            || value.contains('#')
            || value.contains('@')
        {
            return Err(NetworkError::InvalidUrl);
        }

        let (scheme, authority) = split_scheme_authority(value)?;
        if !matches!(scheme, "https" | "http") {
            return Err(NetworkError::UnsupportedScheme);
        }

        let host = authority_host(authority)?;
        let class = if is_loopback_host(host) {
            EndpointClass::Loopback
        } else if host.to_ascii_lowercase().ends_with(".onion") {
            EndpointClass::Onion
        } else {
            EndpointClass::Remote
        };

        match class {
            EndpointClass::Remote => {
                if scheme != "https" {
                    return Err(NetworkError::RemotePlaintextDenied);
                }
            }
            EndpointClass::Loopback => {
                if scheme != "https" && !(scheme == "http" && allow_loopback_plaintext) {
                    return Err(NetworkError::LoopbackPlaintextDenied);
                }
            }
            EndpointClass::Onion => {
                if route != PrivacyRoute::Tor {
                    return Err(NetworkError::OnionRequiresTor);
                }
            }
        }

        Ok(Self {
            url: value.to_owned(),
            class,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.url
    }

    pub const fn class(&self) -> EndpointClass {
        self.class
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPrivacyConfig {
    pub route: PrivacyRoute,
    pub proxy: Option<ProxyEndpoint>,
    pub limits: RequestLimits,
    pub metadata: MetadataPolicy,
    pub allow_redirects: bool,
    pub accept_invalid_certificates: bool,
    pub allow_loopback_plaintext: bool,
}

impl Default for NetworkPrivacyConfig {
    fn default() -> Self {
        Self {
            route: PrivacyRoute::Direct,
            proxy: None,
            limits: RequestLimits::default(),
            metadata: MetadataPolicy::default(),
            allow_redirects: false,
            accept_invalid_certificates: false,
            allow_loopback_plaintext: true,
        }
    }
}

impl NetworkPrivacyConfig {
    pub fn validate(&self) -> Result<(), NetworkError> {
        self.limits.validate()?;
        if self.allow_redirects || self.accept_invalid_certificates {
            return Err(NetworkError::UnsafeTransportPolicy);
        }
        match (self.route, &self.proxy) {
            (PrivacyRoute::Direct, None) => {}
            (PrivacyRoute::Direct, Some(_)) => return Err(NetworkError::UnexpectedProxy),
            (PrivacyRoute::Proxy | PrivacyRoute::Tor, None) => {
                return Err(NetworkError::ProxyRequired);
            }
            (PrivacyRoute::Proxy | PrivacyRoute::Tor, Some(proxy)) => {
                ProxyEndpoint::new(proxy.as_str(), self.route)?;
            }
        }
        Ok(())
    }

    pub fn validate_target(&self, value: &str) -> Result<OutboundTarget, NetworkError> {
        self.validate()?;
        OutboundTarget::new(value, self.route, self.allow_loopback_plaintext)
    }

    pub const fn tls_fail_closed(&self) -> bool {
        !self.accept_invalid_certificates
    }

    pub const fn privacy_hardened(&self) -> bool {
        !self.allow_redirects && !self.accept_invalid_certificates && self.metadata.minimized()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    InvalidUrl,
    UnsupportedScheme,
    RemotePlaintextDenied,
    LoopbackPlaintextDenied,
    OnionRequiresTor,
    InvalidProxy,
    InvalidTorProxy,
    UnexpectedProxy,
    ProxyRequired,
    InvalidLimits,
    UnsafeTransportPolicy,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => write!(formatter, "invalid outbound URL"),
            Self::UnsupportedScheme => write!(formatter, "unsupported outbound URL scheme"),
            Self::RemotePlaintextDenied => {
                write!(formatter, "remote plaintext transport is denied")
            }
            Self::LoopbackPlaintextDenied => {
                write!(formatter, "loopback plaintext transport is denied")
            }
            Self::OnionRequiresTor => write!(formatter, "onion services require Tor routing"),
            Self::InvalidProxy => write!(formatter, "invalid proxy endpoint"),
            Self::InvalidTorProxy => write!(formatter, "Tor proxy must be loopback socks5h"),
            Self::UnexpectedProxy => write!(formatter, "direct routing cannot use a proxy"),
            Self::ProxyRequired => write!(formatter, "selected privacy route requires a proxy"),
            Self::InvalidLimits => write!(formatter, "invalid network request limits"),
            Self::UnsafeTransportPolicy => write!(formatter, "unsafe transport policy is disabled"),
        }
    }
}

impl Error for NetworkError {}

fn split_scheme_authority(value: &str) -> Result<(&str, &str), NetworkError> {
    let (scheme, rest) = value.split_once("://").ok_or(NetworkError::InvalidUrl)?;
    if scheme.is_empty() || rest.is_empty() {
        return Err(NetworkError::InvalidUrl);
    }
    let authority = rest
        .split(['/', '?'])
        .next()
        .filter(|authority| !authority.is_empty())
        .ok_or(NetworkError::InvalidUrl)?;
    Ok((scheme, authority))
}

fn authority_host(authority: &str) -> Result<&str, NetworkError> {
    if authority.starts_with('[') {
        let end = authority.find(']').ok_or(NetworkError::InvalidUrl)?;
        let host = authority.get(1..end).ok_or(NetworkError::InvalidUrl)?;
        if host.is_empty() {
            return Err(NetworkError::InvalidUrl);
        }
        let remainder = authority.get(end + 1..).ok_or(NetworkError::InvalidUrl)?;
        if !remainder.is_empty()
            && (!remainder.starts_with(':')
                || remainder.len() == 1
                || !remainder[1..].bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(NetworkError::InvalidUrl);
        }
        return Ok(host);
    }

    let host = authority.split(':').next().unwrap_or_default();
    if host.is_empty() {
        return Err(NetworkError::InvalidUrl);
    }
    if authority.matches(':').count() > 1 {
        return Err(NetworkError::InvalidUrl);
    }
    if let Some((_, port)) = authority.split_once(':')
        && (port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(NetworkError::InvalidUrl);
    }
    Ok(host)
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    IpAddr::from_str(host).is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_outbound_only() {
        assert!(NetworkPolicy::default().outbound_only());
    }

    #[test]
    fn default_privacy_config_fails_closed_and_minimizes_metadata() {
        let config = NetworkPrivacyConfig::default();
        assert_eq!(config.route, PrivacyRoute::Direct);
        assert!(config.validate().is_ok());
        assert!(config.tls_fail_closed());
        assert!(config.privacy_hardened());
        assert!(!config.allow_redirects);
        assert!(config.metadata.minimized());
    }

    #[test]
    fn remote_plaintext_and_credentials_are_rejected() {
        let config = NetworkPrivacyConfig::default();
        assert_eq!(
            config.validate_target("http://example.com").unwrap_err(),
            NetworkError::RemotePlaintextDenied
        );
        assert_eq!(
            config
                .validate_target("https://user:pass@example.com")
                .unwrap_err(),
            NetworkError::InvalidUrl
        );
    }

    #[test]
    fn https_remote_and_explicit_loopback_http_are_allowed() {
        let config = NetworkPrivacyConfig::default();
        let remote = config.validate_target("https://example.com/api").unwrap();
        assert_eq!(remote.class(), EndpointClass::Remote);

        let local = config
            .validate_target("http://127.0.0.1:18081/json_rpc")
            .unwrap();
        assert_eq!(local.class(), EndpointClass::Loopback);
    }

    #[test]
    fn onion_requires_tor_and_tor_proxy_must_be_loopback_socks5h() {
        let direct = NetworkPrivacyConfig::default();
        assert_eq!(
            direct
                .validate_target("http://examplehiddenservice.onion")
                .unwrap_err(),
            NetworkError::OnionRequiresTor
        );

        let tor = NetworkPrivacyConfig {
            route: PrivacyRoute::Tor,
            proxy: Some(ProxyEndpoint::new("socks5h://127.0.0.1:9050", PrivacyRoute::Tor).unwrap()),
            ..NetworkPrivacyConfig::default()
        };
        assert!(tor.validate().is_ok());
        assert_eq!(
            tor.validate_target("http://examplehiddenservice.onion")
                .unwrap()
                .class(),
            EndpointClass::Onion
        );
        assert!(ProxyEndpoint::new("socks5h://10.0.0.5:9050", PrivacyRoute::Tor).is_err());
    }

    #[test]
    fn unsafe_redirect_and_certificate_policies_are_rejected() {
        let redirects = NetworkPrivacyConfig {
            allow_redirects: true,
            ..NetworkPrivacyConfig::default()
        };
        assert_eq!(
            redirects.validate().unwrap_err(),
            NetworkError::UnsafeTransportPolicy
        );

        let invalid_certs = NetworkPrivacyConfig {
            accept_invalid_certificates: true,
            ..NetworkPrivacyConfig::default()
        };
        assert_eq!(
            invalid_certs.validate().unwrap_err(),
            NetworkError::UnsafeTransportPolicy
        );
    }

    #[test]
    fn proxy_routes_require_valid_proxy_endpoint() {
        let missing = NetworkPrivacyConfig {
            route: PrivacyRoute::Proxy,
            ..NetworkPrivacyConfig::default()
        };
        assert_eq!(missing.validate().unwrap_err(), NetworkError::ProxyRequired);

        let proxy = NetworkPrivacyConfig {
            route: PrivacyRoute::Proxy,
            proxy: Some(ProxyEndpoint::new("https://127.0.0.1:8443", PrivacyRoute::Proxy).unwrap()),
            ..NetworkPrivacyConfig::default()
        };
        assert!(proxy.validate().is_ok());
    }

    #[test]
    fn request_limits_are_bounded() {
        assert!(RequestLimits::default().validate().is_ok());
        assert!(
            RequestLimits {
                connect_timeout_secs: 61,
                ..RequestLimits::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            RequestLimits {
                max_response_bytes: 128 * 1024 * 1024,
                ..RequestLimits::default()
            }
            .validate()
            .is_err()
        );
    }
}
