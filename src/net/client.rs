//! mTLS HTTP client implementation.
//!
//! This module provides a basic HTTP client with mTLS support using Rustls.

use crate::error::{DeTlsError, Result};
use crate::net::config::TlsConfig;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::{Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::str::FromStr;

/// HTTP method enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// GET method
    Get,
    /// POST method
    Post,
    /// PUT method
    Put,
    /// DELETE method
    Delete,
}

impl HttpMethod {
    /// Convert to HTTP method string.
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// HTTP response structure.
#[derive(Debug)]
pub struct HttpResponse {
    /// HTTP status code
    pub status_code: u16,
    /// Response headers
    pub headers: Vec<(String, String)>,
    /// Response body
    pub body: Vec<u8>,
}

/// Perform an mTLS HTTP request.
///
/// This is a simplified implementation that demonstrates the mTLS concept.
/// In a production system, you would use a full HTTP client library.
///
/// # Arguments
///
/// * `url` - The URL to request
/// * `method` - The HTTP method
/// * `config` - The Rustls client configuration with mTLS settings
/// * `body` - Optional request body
///
/// # Example
///
/// ```rust,no_run
/// use detls::net::client::{mtls_request, HttpMethod};
/// use detls::net::config::build_mtls_config;
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use detls::cert::ca::create_root_ca;
///
/// # async fn example() -> detls::error::Result<()> {
/// let keypair = generate_ed25519_keypair()?;
/// let cert = create_root_ca(&keypair, "CN=Client", 365)?;
/// let ca_cert = create_root_ca(&keypair, "CN=CA", 365)?;
/// let config = build_mtls_config(&cert, &keypair, &[ca_cert])?;
///
/// let response = mtls_request(
///     "https://example.com",
///     HttpMethod::Get,
///     config,
///     None,
/// ).await?;
/// println!("Status: {}", response.status_code);
/// # Ok(())
/// # }
/// ```
pub async fn mtls_request(
    url: &str,
    method: HttpMethod,
    config: TlsConfig,
    body: Option<&[u8]>,
) -> Result<HttpResponse> {
    // Parse URL
    let uri =
        Uri::from_str(url).map_err(|e| DeTlsError::ParseError(format!("Invalid URL: {}", e)))?;

    // Check if HTTPS
    if uri.scheme_str() != Some("https") {
        return Err(DeTlsError::NetworkError(
            "Only HTTPS URLs are supported for mTLS".to_string(),
        ));
    }

    // Create HTTPS connector with Rustls
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config((*config.client_config).clone())
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();

    // Create HTTP client
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    // Build request
    let req_builder = Request::builder().uri(uri).method(method.as_str());

    let req = if let Some(body_data) = body {
        req_builder
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", body_data.len())
            .body(Empty::new())
            .map_err(|e| DeTlsError::NetworkError(format!("Failed to build request: {}", e)))?
    } else {
        req_builder
            .body(Empty::new())
            .map_err(|e| DeTlsError::NetworkError(format!("Failed to build request: {}", e)))?
    };

    // Send request
    let res = client
        .request(req)
        .await
        .map_err(|e| DeTlsError::NetworkError(format!("Request failed: {}", e)))?;

    // Extract status code
    let status_code = res.status().as_u16();

    // Extract headers
    let headers: Vec<(String, String)> = res
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();

    // Read response body
    let body_bytes = res
        .into_body()
        .collect()
        .await
        .map_err(|e| DeTlsError::NetworkError(format!("Failed to read response body: {}", e)))?
        .to_bytes()
        .to_vec();

    Ok(HttpResponse {
        status_code,
        headers,
        body: body_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_as_str() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
    }

    #[test]
    fn test_http_method_equality() {
        assert_eq!(HttpMethod::Get, HttpMethod::Get);
        assert_ne!(HttpMethod::Get, HttpMethod::Post);
    }
}
