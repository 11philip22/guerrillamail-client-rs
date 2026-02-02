//! GuerrillaMail async client implementation.
//!
//! This module provides an async [`Client`] and [`ClientBuilder`] for interacting with
//! the GuerrillaMail temporary email service.
//!
//! Typical flow:
//! 1) Build a client (`Client::new` or `Client::builder().build()`)
//! 2) Create an address via [`Client::create_email`]
//! 3) Poll the inbox via [`Client::get_messages`]
//! 4) Fetch full message content via [`Client::fetch_email`]
//! 5) Optionally forget the address via [`Client::delete_email`]

use crate::{Attachment, Error, Message, Result};
use regex::Regex;
use reqwest::StatusCode;
use reqwest::header::{
    ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, HOST, HeaderMap, HeaderValue, ORIGIN, REFERER,
    USER_AGENT,
};
use reqwest::Url;
use std::borrow::Cow;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Async client for the GuerrillaMail temporary email service.
///
/// A `Client` is cheap to clone at the `reqwest` level (internally shared connection pool),
/// and this type is `Clone`. Create it once and clone as needed.
///
/// Construction requires a bootstrap request to GuerrillaMail in order to extract the
/// per-session API token from the homepage HTML. See [`Client::new`] and [`Client::builder`].
///
/// # Notes
/// - GuerrillaMail addresses are represented by an *alias* (the part before `@`) plus a domain.
///   Several API calls only use the alias; this client extracts it automatically.
/// - All methods are async and require a Tokio runtime (or any runtime compatible with `reqwest`).
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    api_token_header: HeaderValue,
    proxy: Option<String>,
    user_agent: String,
    ajax_url: String,
    base_url: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("http", &"<reqwest::Client>")
            .field("api_token_header", &"<redacted>")
            .field("proxy", &self.proxy)
            .field("user_agent", &self.user_agent)
            .field("ajax_url", &self.ajax_url)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl Client {
    /// Create a [`ClientBuilder`] for configuring a new client.
    ///
    /// Use this when you need to set a proxy, change TLS behavior, or override the user agent.
    ///
    /// # Examples
    /// ```no_run
    /// # use guerrillamail_client::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), guerrillamail_client::Error> {
    /// let client = Client::builder()
    ///     .user_agent("my-app/1.0")
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Create a new GuerrillaMail client using default settings.
    ///
    /// This performs a bootstrap request to GuerrillaMail to retrieve the per-session
    /// API token used for subsequent AJAX requests.
    ///
    /// If you need a proxy or stricter TLS verification, prefer [`Client::builder`].
    ///
    /// # Errors
    /// Returns an error if the bootstrap request fails, or if the API token cannot be
    /// parsed from the homepage HTML.
    ///
    /// # Examples
    /// ```no_run
    /// # use guerrillamail_client::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), guerrillamail_client::Error> {
    /// let client = Client::new().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new() -> Result<Self> {
        ClientBuilder::new().build().await
    }

    /// Get the proxy URL configured for this client (if any).
    ///
    /// Returns `None` when no proxy was set on the builder.
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
    }

    /// Create a temporary email address for the given alias.
    ///
    /// GuerrillaMail addresses are conceptually `alias@<domain>`. This call asks the service
    /// to assign the requested alias and returns the full email address as a string.
    ///
    /// # Arguments
    /// * `alias` - The desired local-part (before the `@`).
    ///
    /// # Returns
    /// The full email address assigned by GuerrillaMail (e.g. `myalias@sharklasers.com`).
    ///
    /// # Errors
    /// Returns an error if the request fails or if the response does not include an email address.
    ///
    /// # Examples
    /// ```no_run
    /// # use guerrillamail_client::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), guerrillamail_client::Error> {
    /// let client = Client::new().await?;
    /// let email = client.create_email("myalias").await?;
    /// println!("{email}");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_email(&self, alias: &str) -> Result<String> {
        let params = vec![("f", Cow::Borrowed("set_email_user"))];
        let form = vec![
            ("email_user", Cow::Owned(alias.to_string())),
            ("lang", Cow::Borrowed("en")),
            ("site", Cow::Borrowed("guerrillamail.com")),
            ("in", Cow::Borrowed(" Set cancel")),
        ];

        let response = self
            .request_json(ApiMethod::Post, &self.ajax_url, &params, Some(&form))
            .await?;

        let email_addr = response
            .get("email_addr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::ResponseParseContext {
                    msg: format!(
                        "missing or non-string `email_addr` (response: {})",
                        Self::json_snippet(&response)
                    ),
                }
            })?;

        Ok(email_addr.to_string())
    }

    /// Retrieve the current inbox messages for the given email address.
    ///
    /// This calls GuerrillaMail's `check_email` endpoint. Only the alias portion of the
    /// email is used by the underlying API; the client extracts it automatically.
    ///
    /// # Arguments
    /// * `email` - A full email address (e.g. `alias@domain.tld`).
    ///
    /// # Returns
    /// A list of inbox messages (headers/summary fields).
    ///
    /// # Errors
    /// Returns an error if the request fails or if the server response is not valid JSON.
    ///
    /// # Examples
    /// ```no_run
    /// # use guerrillamail_client::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), guerrillamail_client::Error> {
    /// let client = Client::new().await?;
    /// let email = client.create_email("myalias").await?;
    /// let messages = client.get_messages(&email).await?;
    /// for msg in messages {
    ///     println!("{}: {}", msg.mail_from, msg.mail_subject);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_messages(&self, email: &str) -> Result<Vec<Message>> {
        let params = self.api_params("check_email", email, None);
        let response = self
            .request_json(ApiMethod::Get, &self.ajax_url, &params, None)
            .await?;

        let list = response
            .get("list")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::ResponseParseContext {
                msg: format!(
                    "missing or non-array `list` (response: {})",
                    Self::json_snippet(&response)
                ),
            })?;

        let messages = list
            .iter()
            .map(|v| serde_json::from_value::<Message>(v.clone()).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;

        Ok(messages)
    }

    /// Fetch the full content of a specific message.
    ///
    /// Use [`Client::get_messages`] to list messages and obtain a `mail_id`, then call this
    /// method to retrieve the full message body and details.
    ///
    /// # Arguments
    /// * `email` - A full email address (used to derive the alias for the API call).
    /// * `mail_id` - The message id returned by the inbox listing.
    ///
    /// # Returns
    /// An [`EmailDetails`](crate::EmailDetails) struct containing full message metadata and body.
    ///
    /// # Errors
    /// Returns an error if the request fails or if the JSON response cannot be deserialized.
    ///
    /// # Examples
    /// ```no_run
    /// # use guerrillamail_client::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), guerrillamail_client::Error> {
    /// let client = Client::new().await?;
    /// let email = client.create_email("myalias").await?;
    /// let messages = client.get_messages(&email).await?;
    /// if let Some(msg) = messages.first() {
    ///     let details = client.fetch_email(&email, &msg.mail_id).await?;
    ///     println!("{}", details.mail_body);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch_email(&self, email: &str, mail_id: &str) -> Result<crate::EmailDetails> {
        let params = self.api_params("fetch_email", email, Some(mail_id));
        self.request(ApiMethod::Get, &self.ajax_url, &params, None).await
    }

    /// List attachment metadata for a message.
    ///
    /// This is a convenience wrapper around [`Client::fetch_email`] that returns
    /// the attachment list (if any).
    pub async fn list_attachments(&self, email: &str, mail_id: &str) -> Result<Vec<Attachment>> {
        let details = self.fetch_email(email, mail_id).await?;
        Ok(details.attachments)
    }

    /// Download an attachment for a message.
    ///
    /// The GuerrillaMail API may return a `sid_token` as part of `fetch_email`. When present,
    /// it is included in the download request. If no token is provided, the request relies
    /// on the existing session cookies.
    ///
    /// Prefer [`Client::fetch_attachment_with_sid`] when you already have a `sid_token`
    /// to avoid the extra `fetch_email` round-trip per attachment.
    ///
    /// # Errors
    /// Returns an error if:
    /// - the attachment does not include a part id,
    /// - the request fails,
    /// - the server returns a non-success status.
    ///
    /// # Examples
    /// ```no_run
    /// # use guerrillamail_client::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), guerrillamail_client::Error> {
    /// let client = Client::new().await?;
    /// let email = client.create_email("myalias").await?;
    /// let messages = client.get_messages(&email).await?;
    /// if let Some(msg) = messages.first() {
    ///     let attachments = client.list_attachments(&email, &msg.mail_id).await?;
    ///     if let Some(attachment) = attachments.first() {
    ///         let bytes = client.fetch_attachment(&email, &msg.mail_id, attachment).await?;
    ///         println!("Downloaded {} bytes", bytes.len());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch_attachment(
        &self,
        email: &str,
        mail_id: &str,
        attachment: &Attachment,
    ) -> Result<Vec<u8>> {
        if attachment.part_id.trim().is_empty() {
            return Err(Error::ResponseParseContext {
                msg: "attachment missing part_id".to_string(),
            });
        }
        if mail_id.trim().is_empty() {
            return Err(Error::ResponseParseContext {
                msg: "missing mail_id for attachment download".to_string(),
            });
        }

        let details = self.fetch_email(email, mail_id).await?;
        let sid_token = details.sid_token.as_deref().unwrap_or("");

        self.fetch_attachment_with_sid(mail_id, sid_token, attachment)
            .await
    }

    /// Download an attachment when you already possess a `sid_token`.
    ///
    /// Prefer this method if you've just called [`Client::fetch_email`] and can reuse
    /// the returned `sid_token`; it avoids an extra network request per attachment.
    ///
    /// # Arguments
    /// * `mail_id` - Message identifier.
    /// * `sid_token` - Session token returned by `fetch_email`.
    /// * `attachment` - Attachment metadata entry.
    pub async fn fetch_attachment_with_sid(
        &self,
        mail_id: &str,
        sid_token: &str,
        attachment: &Attachment,
    ) -> Result<Vec<u8>> {
        if attachment.part_id.trim().is_empty() {
            return Err(Error::ResponseParseContext {
                msg: "attachment missing part_id".to_string(),
            });
        }
        if mail_id.trim().is_empty() {
            return Err(Error::ResponseParseContext {
                msg: "missing mail_id for attachment download".to_string(),
            });
        }

        let inbox_url = self.inbox_url();

        let mut query = vec![
            ("get_att", Cow::Borrowed("")),
            ("lang", Cow::Borrowed("en")),
            ("email_id", Cow::Owned(mail_id.to_string())),
            ("part_id", Cow::Owned(attachment.part_id.clone())),
        ];

        if !sid_token.trim().is_empty() {
            query.push(("sid_token", Cow::Owned(sid_token.to_string())));
        }

        let bytes = self
            .request_bytes(ApiMethod::Get, &inbox_url, &query, None)
            .await?;

        Ok(bytes)
    }

    /// Forget/delete the given email address from the current session.
    ///
    /// This calls GuerrillaMail's `forget_me` action. The service uses the alias portion of the
    /// address; the client extracts it automatically.
    ///
    /// # Arguments
    /// * `email` - The full email address to forget.
    ///
    /// # Returns
    /// `Ok(())` on HTTP success; non-2xx responses surface as errors with context.
    ///
    /// # Notes
    /// This method does not guarantee the address becomes unusable globally—it only requests
    /// GuerrillaMail to forget it for the current session.
    ///
    /// # Examples
    /// ```no_run
    /// # use guerrillamail_client::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), guerrillamail_client::Error> {
    /// let client = Client::new().await?;
    /// let email = client.create_email("myalias").await?;
    /// client.delete_email(&email).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_email(&self, email: &str) -> Result<()> {
        let alias = Self::extract_alias(email);
        let params = vec![("f", Cow::Borrowed("forget_me"))];
        let form = vec![
            ("site", Cow::Borrowed("guerrillamail.com")),
            ("in", Cow::Borrowed(alias)),
        ];

        self.request_status(ApiMethod::Post, &self.ajax_url, &params, Some(&form))
            .await?;
        Ok(())
    }

    async fn request_json(
        &self,
        method: ApiMethod,
        url: &str,
        params: &[Param<'_>],
        form: Option<&[Param<'_>]>,
    ) -> Result<serde_json::Value> {
        self.request(method, url, params, form).await
    }

    async fn request_bytes(
        &self,
        method: ApiMethod,
        url: &str,
        params: &[Param<'_>],
        form: Option<&[Param<'_>]>,
    ) -> Result<Vec<u8>> {
        let (_status, body) = self.execute_request(method, url, params, form, true, true).await?;
        Ok(body)
    }

    async fn request_status(
        &self,
        method: ApiMethod,
        url: &str,
        params: &[Param<'_>],
        form: Option<&[Param<'_>]>,
    ) -> Result<StatusCode> {
        let mut headers = self.headers();
        if matches!(method, ApiMethod::Get) {
            headers.remove(CONTENT_TYPE);
        }

        #[cfg(feature = "debug_responses")]
        self.log_request(method, url, params);

        let response = self
            .build_request(method, url, params, form)
            .headers(headers)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            return Ok(status);
        }

        // Read a small body snippet for diagnostics without wasting too much bandwidth.
        let body_snippet = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string())
            .chars()
            .take(512)
            .collect::<String>();

        Err(Error::ResponseParseContext {
            msg: format!(
                "HTTP {} for {} (body snippet: {})",
                status.as_u16(),
                url,
                body_snippet
            ),
        })
    }

    async fn request<T>(
        &self,
        method: ApiMethod,
        url: &str,
        params: &[Param<'_>],
        form: Option<&[Param<'_>]>,
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let (_status, body) = self.execute_request(method, url, params, form, true, true).await?;
        let parsed = serde_json::from_slice::<T>(&body)?;
        Ok(parsed)
    }

    async fn execute_request(
        &self,
        method: ApiMethod,
        url: &str,
        params: &[Param<'_>],
        form: Option<&[Param<'_>]>,
        log_body: bool,
        fail_on_status: bool,
    ) -> Result<(StatusCode, Vec<u8>)> {
        #[cfg(not(feature = "debug_responses"))]
        let _ = log_body;

        let mut headers = self.headers();
        if matches!(method, ApiMethod::Get) {
            headers.remove(CONTENT_TYPE);
        }

        #[cfg(feature = "debug_responses")]
        self.log_request(method, url, params);

        let response = self
            .build_request(method, url, params, form)
            .headers(headers)
            .send()
            .await?;

        let status = response.status();
        let status_err = if fail_on_status {
            response.error_for_status_ref().err()
        } else {
            None
        };
        let body = response.bytes().await?;

        #[cfg(feature = "debug_responses")]
        if log_body {
            self.log_response(status, &body);
        }

        if let Some(err) = status_err {
            return Err(err.into());
        }

        Ok((status, body.to_vec()))
    }

    /// Extract the alias (local-part) from a full email address.
    ///
    /// If the string does not contain `@`, the full input is returned unchanged.
    fn extract_alias(email: &str) -> &str {
        email.split('@').next().unwrap_or(email)
    }

    fn api_params(&self, function: &str, email: &str, email_id: Option<&str>) -> Vec<Param<'_>> {
        let alias = Self::extract_alias(email);
        let timestamp = Self::timestamp();

        let mut params = vec![
            ("f", Cow::Borrowed(function)),
            ("site", Cow::Borrowed("guerrillamail.com")),
            ("in", Cow::Owned(alias.to_string())),
            ("_", Cow::Owned(timestamp)),
        ];

        if let Some(id) = email_id {
            params.insert(1, ("email_id", Cow::Owned(id.to_string())));
        }

        if function == "check_email" {
            params.insert(1, ("seq", Cow::Borrowed("1")));
        }

        params
    }

    fn build_request(
        &self,
        method: ApiMethod,
        url: &str,
        params: &[Param<'_>],
        form: Option<&[Param<'_>]>,
    ) -> reqwest::RequestBuilder {
        match method {
            ApiMethod::Get => self.http.get(url).query(params),
            ApiMethod::Post => {
                let mut req = self.http.post(url).query(params);
                if let Some(form_params) = form {
                    req = req.form(form_params);
                }
                req
            }
        }
    }

    #[cfg(feature = "debug_responses")]
    fn log_request(&self, method: ApiMethod, url: &str, params: &[Param<'_>]) {
        eprintln!("GuerrillaMail API request: {:?} {}", method, url);
        if params.is_empty() {
            eprintln!("Query: <none>");
        } else {
            let mut parts = Vec::with_capacity(params.len());
            for (key, value) in params {
                let is_token = key.to_lowercase().contains("token");
                let safe_value = if is_token {
                    "<redacted>"
                } else {
                    value.as_ref()
                };
                parts.push(format!("{key}={safe_value}"));
            }
            eprintln!("Query: {}", parts.join("&"));
        }
    }

    #[cfg(feature = "debug_responses")]
    fn log_response(&self, status: StatusCode, body: &[u8]) {
        eprintln!("GuerrillaMail API response (status={}):", status.as_str());

        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) {
            self.redact_tokens_in_value(&mut value);
            if let Ok(pretty) = serde_json::to_string_pretty(&value) {
                eprintln!("{pretty}");
                return;
            }
        }

        let body_text = String::from_utf8_lossy(body);
        eprintln!("{}", self.redact_tokens_in_text(&body_text));
    }

    #[cfg(feature = "debug_responses")]
    fn redact_tokens_in_value(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    if key.to_lowercase().contains("token") {
                        *val = serde_json::Value::String("<redacted>".to_string());
                    } else {
                        self.redact_tokens_in_value(val);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    self.redact_tokens_in_value(item);
                }
            }
            _ => {}
        }
    }

    #[cfg(feature = "debug_responses")]
    fn redact_tokens_in_text(&self, raw: &str) -> String {
        let mut redacted = raw.to_string();

        let patterns = [
            r#"(?i)("sid_token"\s*:\s*")[^"]*(")"#,
            r#"(?i)("api_token"\s*:\s*")[^"]*(")"#,
            r#"(?i)("token"\s*:\s*")[^"]*(")"#,
            r#"(?i)(sid_token=)[^&\s"]+"#,
            r#"(?i)(api_token=)[^&\s"]+"#,
            r#"(?i)(token=)[^&\s"]+"#,
            r#"(?i)(ApiToken\s+)[A-Za-z0-9]+"#,
            r#"(?i)(PHPSESSID=)[^;\s"]+"#,
        ];

        for pattern in patterns {
            if let Ok(re) = Regex::new(pattern) {
                redacted = re
                    .replace_all(&redacted, |caps: &regex::Captures<'_>| {
                        if caps.len() >= 3 {
                            format!("{}<redacted>{}", &caps[1], &caps[2])
                        } else if caps.len() == 2 {
                            format!("{}<redacted>", &caps[1])
                        } else {
                            "<redacted>".to_string()
                        }
                    })
                    .to_string();
            }
        }

        redacted
    }

    fn inbox_url(&self) -> String {
        format!("{}/inbox", self.base_url.trim_end_matches('/'))
    }

    fn json_snippet(value: &serde_json::Value) -> String {
        let raw = value.to_string();
        raw.chars().take(200).collect()
    }

    /// Generate a millisecond timestamp suitable for cache-busting query parameters.
    ///
    /// # Panics
    ///
    /// Panics if the system clock is before the Unix epoch. This indicates a
    /// misconfigured or broken system clock and is treated as a fatal error.
    fn timestamp() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before UNIX_EPOCH")
            .as_millis()
            .to_string()
    }

    /// Construct the HTTP headers used for GuerrillaMail AJAX requests.
    ///
    /// Includes the GuerrillaMail `ApiToken` authorization header extracted during bootstrap.
    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();

        if let Ok(value) = HeaderValue::from_str(&self.user_agent) {
            headers.insert(USER_AGENT, value);
        }
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/javascript, */*; q=0.01"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        headers.insert("Authorization", self.api_token_header.clone());
        headers.insert(
            "X-Requested-With",
            HeaderValue::from_static("XMLHttpRequest"),
        );
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-origin"));
        headers.insert("Priority", HeaderValue::from_static("u=0"));

        if let Some((host_header, origin_header, referer_header)) =
            self.derived_origin_headers(&self.ajax_url, &self.base_url)
        {
            headers.insert(HOST, host_header);
            headers.insert(ORIGIN, origin_header);
            headers.insert(REFERER, referer_header);
        }

        headers
    }

    fn derived_origin_headers(
        &self,
        ajax_url: &str,
        base_url: &str,
    ) -> Option<(HeaderValue, HeaderValue, HeaderValue)> {
        let ajax = Url::parse(ajax_url).ok()?;
        let host = ajax.host_str()?;
        let host_port = match ajax.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };

        let origin_str = format!("{}://{}", ajax.scheme(), host_port);
        let referer_str = Url::parse(base_url)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| ajax.to_string());

        let host_header = HeaderValue::from_str(&host_port).ok()?;
        let origin_header = HeaderValue::from_str(&origin_str).ok()?;
        let referer_header = HeaderValue::from_str(&referer_str).ok()?;

        Some((host_header, origin_header, referer_header))
    }
}

const BASE_URL: &str = "https://www.guerrillamail.com";
const AJAX_URL: &str = "https://www.guerrillamail.com/ajax.php";
const USER_AGENT_VALUE: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0";

/// Builder for configuring a GuerrillaMail [`Client`].
///
/// Start with [`Client::builder`] to override defaults, then call [`ClientBuilder::build`]
/// to perform the bootstrap request and construct the client.
///
/// # Defaults
/// - No proxy
/// - `danger_accept_invalid_certs = true` (convenient for interception/testing)
/// - A browser-like user agent
/// - The default GuerrillaMail AJAX endpoint
/// - The default GuerrillaMail base URL
/// - Reqwest default timeout
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    proxy: Option<String>,
    danger_accept_invalid_certs: bool,
    user_agent: String,
    ajax_url: String,
    base_url: String,
    timeout: Option<Duration>,
}

type Param<'a> = (&'a str, Cow<'a, str>);

#[derive(Copy, Clone, Debug)]
enum ApiMethod {
    Get,
    Post,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    /// Create a new builder with default settings.
    ///
    /// See [`ClientBuilder`] for the list of defaults.
    pub fn new() -> Self {
        Self {
            proxy: None,
            danger_accept_invalid_certs: true,
            user_agent: USER_AGENT_VALUE.to_string(),
            ajax_url: AJAX_URL.to_string(),
            base_url: BASE_URL.to_string(),
            timeout: None,
        }
    }

    /// Set a proxy URL (e.g. `"http://127.0.0.1:8080"`).
    ///
    /// The proxy is applied to all requests performed by the underlying `reqwest::Client`.
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Configure whether to accept invalid TLS certificates (default: `true`).
    ///
    /// Set this to `false` for stricter TLS verification.
    ///
    /// # Security
    /// Accepting invalid certificates is unsafe on untrusted networks; it is primarily useful
    /// for debugging or traffic inspection in controlled environments.
    pub fn danger_accept_invalid_certs(mut self, value: bool) -> Self {
        self.danger_accept_invalid_certs = value;
        self
    }

    /// Override the default user agent string.
    ///
    /// GuerrillaMail may apply different behavior based on the UA; the default is a
    /// browser-like value.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Override the GuerrillaMail AJAX endpoint URL.
    ///
    /// This is primarily useful for testing or if GuerrillaMail changes its endpoint.
    pub fn ajax_url(mut self, ajax_url: impl Into<String>) -> Self {
        self.ajax_url = ajax_url.into();
        self
    }

    /// Override the GuerrillaMail base URL.
    ///
    /// This is primarily useful for testing.
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set a request timeout applied to all operations.
    ///
    /// Defaults to reqwest's built-in timeout when not specified.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Build the [`Client`] by performing the bootstrap request.
    ///
    /// This creates an underlying `reqwest::Client` (with cookie storage enabled), performs
    /// a request to the GuerrillaMail homepage, and extracts the `api_token` required for
    /// subsequent AJAX calls.
    ///
    /// # Errors
    /// Returns an error if:
    /// - the HTTP client cannot be constructed (e.g., invalid proxy URL),
    /// - the bootstrap request fails,
    /// - the `api_token` cannot be parsed from the response.
    ///
    /// # Examples
    /// ```no_run
    /// # use guerrillamail_client::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), guerrillamail_client::Error> {
    /// let client = Client::builder()
    ///     .user_agent("my-app/1.0")
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn build(self) -> Result<Client> {
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.danger_accept_invalid_certs);

        if let Some(proxy_url) = &self.proxy {
            builder = builder.proxy(reqwest::Proxy::all(proxy_url)?);
        }

        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }

        // Enable cookie store to persist session between requests.
        let http = builder.cookie_store(true).build()?;

        // Fetch the main page to get API token.
        let response = http.get(&self.base_url).send().await?.text().await?;

        // Parse API token: api_token : 'xxxxxxxx' (accepts common token characters)
        let token_re = Regex::new(r"api_token\s*:\s*'([^']+)'")?;
        let api_token = token_re
            .captures(&response)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or(Error::TokenParse)?;
        let api_token_header = HeaderValue::from_str(&format!("ApiToken {}", api_token))?;

        Ok(Client {
            http,
            api_token_header,
            proxy: self.proxy,
            user_agent: self.user_agent,
            ajax_url: self.ajax_url,
            base_url: self.base_url,
        })
    }
}

#[cfg(test)]
impl Client {
    fn new_for_tests(base_url: String, ajax_url: String) -> Self {
        let http = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .expect("test client build failed");
        let api_token_header = HeaderValue::from_static("ApiToken test");
        Self {
            http,
            api_token_header,
            proxy: None,
            user_agent: USER_AGENT_VALUE.to_string(),
            ajax_url,
            base_url,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;
    use serde_json::json;

    #[tokio::test]
    async fn fetch_attachment_builds_request_and_returns_bytes() {
        let server = MockServer::start();
        let base_url = server.base_url();

        let fetch_email_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/ajax.php")
                .query_param("f", "fetch_email")
                .query_param("email_id", "123");
            then.status(200).json_body(json!({
                "mail_id": 123,
                "mail_from": "sender@example.com",
                "mail_subject": "Subject",
                "mail_body": "<p>Body</p>",
                "mail_timestamp": 1700000000,
                "att": "1",
                "att_info": [{ "f": "file.txt", "t": "text/plain", "p": 99 }],
                "sid_token": "sid123"
            }));
        });

        let attachment_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/inbox")
                .query_param("get_att", "")
                .query_param("lang", "en")
                .query_param("email_id", "123")
                .query_param("part_id", "99")
                .query_param("sid_token", "sid123");
            then.status(200).body("hello");
        });

        let client = Client::new_for_tests(base_url.clone(), format!("{base_url}/ajax.php"));

        let attachment = Attachment {
            filename: "file.txt".to_string(),
            content_type_or_hint: Some("text/plain".to_string()),
            part_id: "99".to_string(),
        };

        let bytes = client
            .fetch_attachment("alias@example.com", "123", &attachment)
            .await
            .unwrap();

        assert_eq!(bytes, b"hello");
        fetch_email_mock.assert();
        attachment_mock.assert();
    }

    #[tokio::test]
    async fn delete_email_propagates_error_on_non_success_status() {
        let server = MockServer::start();
        let base_url = server.base_url();

        let delete_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/ajax.php")
                .query_param("f", "forget_me");
            then.status(500).body("boom");
        });

        let client = Client::new_for_tests(base_url.clone(), format!("{base_url}/ajax.php"));

        let result = client.delete_email("alias@example.com").await;
        assert!(result.is_err(), "expected error on non-2xx delete_email");

        delete_mock.assert();
    }

    #[tokio::test]
    async fn base_url_sets_host_origin_and_referer_headers() {
        let server = MockServer::start();
        let base_url = server.base_url();
        let ajax_url = format!("{base_url}/ajax.php");

        let parsed_ajax = Url::parse(&ajax_url).unwrap();
        let expected_host = match parsed_ajax.port() {
            Some(port) => format!("{}:{}", parsed_ajax.host_str().unwrap(), port),
            None => parsed_ajax.host_str().unwrap().to_string(),
        };

        let get_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/ajax.php")
                .query_param("f", "check_email")
                .header("Host", expected_host.clone())
                .header("Origin", base_url.clone())
                .header("Referer", format!("{base_url}/"));
            then.status(200).json_body(json!({ "list": [] }));
        });

        let client = Client::new_for_tests(base_url, ajax_url);
        let _ = client.get_messages("alias@example.com").await;

        get_mock.assert();
    }

    #[tokio::test]
    async fn fetch_attachment_does_not_refetch_when_sid_token_available() {
        let server = MockServer::start();
        let base_url = server.base_url();
        let ajax_url = format!("{base_url}/ajax.php");

        // Expect no fetch_email call once sid_token can be supplied directly.
        let fetch_email_mock = server
            .mock(|when, then| {
                when.method(GET)
                    .path("/ajax.php")
                    .query_param("f", "fetch_email");
                then.status(200).json_body(json!({ "list": [] }));
            })
            .expect(0);

        let attachment_mock = server.mock(|when, then| {
            when.method(GET)
                .path("/inbox")
                .query_param("get_att", "")
                .query_param("lang", "en")
                .query_param("email_id", "123")
                .query_param("part_id", "99")
                .query_param("sid_token", "sid-123");
            then.status(200).body("hello");
        });

        let client = Client::new_for_tests(base_url.clone(), ajax_url);

        let attachment = Attachment {
            filename: "file.txt".to_string(),
            content_type_or_hint: Some("text/plain".to_string()),
            part_id: "99".to_string(),
        };

        let bytes = client
            .fetch_attachment_with_sid("123", "sid-123", &attachment)
            .await;

        assert!(bytes.is_ok());
        assert_eq!(bytes.unwrap(), b"hello");

        attachment_mock.assert();
        fetch_email_mock.assert();
    }

    #[tokio::test]
    async fn api_token_regex_accepts_common_symbols() {
        let server = MockServer::start();
        let base_url = server.base_url();
        let ajax_url = format!("{base_url}/ajax.php");

        let token = "Abc-123_def.+/=";
        let html = format!("var api_token : '{token}';");

        let _root = server.mock(|when, then| {
            when.method(GET).path("/");
            then.status(200).body(html);
        });

        let builder = ClientBuilder::new()
            .base_url(base_url.clone())
            .ajax_url(ajax_url);

        let client_result = builder.build().await;
        assert!(
            client_result.is_ok(),
            "expected builder to parse tokens with symbols like '-' '.' '+' '/' '='"
        );
    }
}
