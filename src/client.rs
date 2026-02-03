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
use reqwest::{
    header::{
        ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, HOST, HeaderMap, HeaderValue, ORIGIN, REFERER,
        USER_AGENT,
    },
    Url,
};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// High-level async handle to a single GuerrillaMail session.
///
/// Conceptually, a [`Client`] owns the session state needed to talk to the public GuerrillaMail
/// AJAX API: a cookie jar plus the `ApiToken …` header parsed from an initial bootstrap request.
/// Every outbound request reuses prebuilt header maps that always include that token, a
/// browser-like user agent, and the correct host/origin metadata.
///
/// Invariants/internal behavior:
/// - The API token is fetched once during construction and stored as a header; it is never
///   refreshed automatically. Rebuild the client if the token expires.
/// - Addresses are treated as `alias@domain`; when the API only cares about the alias,
///   the client extracts it for you.
/// - The underlying `reqwest::Client` has cookies enabled so successive calls share the same
///   GuerrillaMail session.
///
/// Typical lifecycle: create a client (`Client::new` or `Client::builder().build()`), allocate an
/// address, poll messages, fetch message details/attachments (via [`Message`] and
/// [`crate::EmailDetails`]), then optionally forget the address.
///
/// Concurrency: [`Client`] is `Clone` and cheap to duplicate; clones share the HTTP connection
/// pool, cookies, and token header, making it safe to pass into multiple async tasks.
///
/// # Example
/// ```rust,no_run
/// # use guerrillamail_client::Client;
/// # #[tokio::main]
/// # async fn main() -> Result<(), guerrillamail_client::Error> {
/// let client = Client::new().await?;
/// let email = client.create_email("demo").await?;
/// let messages = client.get_messages(&email).await?;
/// println!("Inbox size: {}", messages.len());
/// client.delete_email(&email).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    #[allow(dead_code)]
    api_token_header: HeaderValue,
    proxy: Option<String>,
    user_agent: String,
    ajax_url: Url,
    base_url: Url,
    ajax_headers: HeaderMap,
    ajax_headers_no_ct: HeaderMap,
    base_headers: HeaderMap,
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

    /// Build a default GuerrillaMail client.
    ///
    /// Performs a single bootstrap GET to the GuerrillaMail homepage, extracts the `ApiToken …`
    /// header, and constructs a session-aware client using default headers and timeouts. The
    /// token is not refreshed automatically; rebuild the client if it expires. Use
    /// [`Client::builder`] when you need proxy/TLS overrides.
    ///
    /// # Errors
    /// - Returns `Error::Request` on bootstrap network failures or any non-2xx response (via `error_for_status`).
    /// - Returns `Error::TokenParse` when the API token cannot be extracted from the homepage HTML.
    /// - Returns `Error::HeaderValue` if the parsed token cannot be encoded into a header.
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

    /// Request a new temporary address for the given alias.
    ///
    /// Sends a POST to the GuerrillaMail AJAX endpoint, asking the service to reserve the supplied
    /// alias and return the full `alias@domain` address. Builds required headers and includes the
    /// session token automatically.
    ///
    /// # Arguments
    /// - `alias`: Desired local-part before `@`.
    ///
    /// # Returns
    /// The full email address assigned by GuerrillaMail (e.g., `myalias@sharklasers.com`).
    ///
    /// # Errors
    /// - Returns `Error::Request` for network failures or non-2xx responses.
    /// - Returns `Error::ResponseParse` if the JSON body lacks a string `email_addr` field.
    /// Network failures are typically transient; parse errors usually indicate an API schema change.
    ///
    /// # Network
    /// Issues one POST request to `ajax.php`.
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
        let params = [("f", "set_email_user")];
        let form = [
            ("email_user", alias),
            ("lang", "en"),
            ("site", "guerrillamail.com"),
            ("in", " Set cancel"),
        ];

        let response: serde_json::Value = self
            .http
            .post(self.ajax_url.as_str())
            .query(&params)
            .form(&form)
            .headers(self.ajax_headers())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let email_addr = response
            .get("email_addr")
            .and_then(|v| v.as_str())
            .ok_or(Error::ResponseParse("missing or non-string `email_addr`"))?;

        Ok(email_addr.to_string())
    }

    /// Fetch the current inbox listing for an address.
    ///
    /// Calls the `check_email` AJAX function using only the alias portion of the provided address.
    /// Includes cache-busting timestamp and required headers; parses the `list` array into
    /// [`Message`] structs.
    ///
    /// # Arguments
    /// - `email`: Full address (alias is extracted automatically).
    ///
    /// # Returns
    /// Vector of message headers/summaries currently in the inbox.
    ///
    /// # Errors
    /// - Returns `Error::Request` for network failures or non-2xx responses.
    /// - Returns `Error::ResponseParse` when the JSON body is missing a `list` array.
    /// - Returns `Error::Json` if individual messages fail to deserialize.
    /// Network issues are transient; parse/deserialize errors generally indicate a schema change.
    ///
    /// # Network
    /// Issues one GET request to `ajax.php` with query parameters.
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
        let response = self.get_api("check_email", email, None).await?;

        let list = response
            .get("list")
            .and_then(|v| v.as_array())
            .ok_or(Error::ResponseParse("missing or non-array `list`"))?;

        let messages = list
            .iter()
            .map(|v| serde_json::from_value::<Message>(v.clone()).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;

        Ok(messages)
    }

    /// Fetch full contents for a message.
    ///
    /// Calls the `fetch_email` AJAX function using the alias derived from the address and the
    /// provided `mail_id`, then deserializes the full message metadata and body.
    ///
    /// # Arguments
    /// - `email`: Full address associated with the message.
    /// - `mail_id`: Identifier obtained from [`get_messages`](Client::get_messages).
    ///
    /// # Returns
    /// [`crate::EmailDetails`] containing body, metadata, attachments, and optional `sid_token`.
    ///
    /// # Errors
    /// - Returns `Error::Request` for network failures or non-2xx responses.
    /// - Returns `Error::Json` if the response body cannot be deserialized into `EmailDetails`.
    /// Network issues are transient; deserialization errors suggest a changed API response.
    ///
    /// # Network
    /// Issues one GET request to `ajax.php`.
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
        let raw = self.get_api_text("fetch_email", email, Some(mail_id)).await?;

        let details = serde_json::from_str::<crate::EmailDetails>(&raw)?;
        Ok(details)
    }

    /// List attachment metadata for a message.
    ///
    /// Convenience wrapper over [`fetch_email`](Client::fetch_email) that extracts the attachment
    /// list from the returned details.
    ///
    /// # Errors
    /// - Propagates any `Error::Request` or parsing errors from [`fetch_email`](Self::fetch_email).
    /// Transient network issues bubble up unchanged; parse errors imply the upstream response shape shifted.
    pub async fn list_attachments(
        &self,
        email: &str,
        mail_id: &str,
    ) -> Result<Vec<Attachment>> {
        let details = self.fetch_email(email, mail_id).await?;
        Ok(details.attachments)
    }

    /// Download an attachment for a message.
    ///
    /// Performs a GET to the inbox download endpoint, including any `sid_token` previously
    /// returned by `fetch_email`. Requires a non-empty `part_id` on the attachment and the
    /// originating `mail_id`.
    ///
    /// # Arguments
    /// - `email`: Full address used to derive the alias for token-related calls.
    /// - `mail_id`: Message id whose attachment is being fetched.
    /// - `attachment`: Attachment metadata containing the part id to retrieve.
    ///
    /// # Returns
    /// Raw bytes of the attachment body.
    ///
    /// # Errors
    /// - Returns `Error::ResponseParse` if `part_id` or `mail_id` are empty.
    /// - Returns `Error::Request` for network failures or non-2xx download responses (via `error_for_status`).
    /// Empty identifiers are permanent until corrected; network and status errors are transient.
    ///
    /// # Network
    /// Issues one GET request to the inbox download endpoint (typically `/inbox`).
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
            return Err(Error::ResponseParse("attachment missing part_id"));
        }

        let details = self.fetch_email(email, mail_id).await?;
        let inbox_url = self.inbox_url();

        let mut query = vec![
            ("get_att", "".to_string()),
            ("lang", "en".to_string()),
            ("email_id", mail_id.to_string()),
            ("part_id", attachment.part_id.clone()),
        ];

        if let Some(token) = details.sid_token.as_deref() {
            if !token.is_empty() {
                query.push(("sid_token", token.to_string()));
            }
        }

        let response = self
            .http
            .get(&inbox_url)
            .query(&query)
            .headers(self.base_headers())
            .send()
            .await?
            .error_for_status()?;

        let bytes = response.bytes().await?;
        Ok(bytes.to_vec())
    }

    /// Ask GuerrillaMail to forget an address for this session.
    ///
    /// Calls the `forget_me` AJAX function using the alias extracted from the provided address.
    /// Only affects the current session; it does not guarantee global deletion of the address.
    ///
    /// # Arguments
    /// - `email`: Full address to remove from the session.
    ///
    /// # Returns
    /// `true` when the HTTP response status is 2xx.
    ///
    /// # Errors
    /// - Returns `Error::Request` for network failures or non-2xx responses from the `forget_me` call.
    /// Network/non-2xx failures are transient; repeated failures may indicate the service endpoint changed.
    ///
    /// # Network
    /// Issues one POST request to `ajax.php`.
    ///
    /// # Examples
    /// ```no_run
    /// # use guerrillamail_client::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), guerrillamail_client::Error> {
    /// let client = Client::new().await?;
    /// let email = client.create_email("myalias").await?;
    /// let ok = client.delete_email(&email).await?;
    /// println!("{ok}");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_email(&self, email: &str) -> Result<bool> {
        let alias = Self::extract_alias(email);
        let params = [("f", "forget_me")];
        let form = [("site", "guerrillamail.com"), ("in", alias)];

        let response = self
            .http
            .post(self.ajax_url.as_str())
            .query(&params)
            .form(&form)
            .headers(self.ajax_headers())
            .send()
            .await?
            .error_for_status()?;

        Ok(response.status().is_success())
    }

    /// Perform a common GuerrillaMail AJAX API call and return the raw JSON value.
    ///
    /// This helper centralizes request construction for endpoints such as `check_email` and
    /// `fetch_email`. It injects a cache-busting timestamp parameter and ensures the correct
    /// authorization header is set.
    ///
    /// # Arguments
    /// * `function` - The GuerrillaMail function name (e.g. `"check_email"`).
    /// * `email` - Full email address (alias will be extracted).
    /// * `email_id` - Optional message id parameter for endpoints that require it.
    ///
    /// # Errors
    /// Returns an error if the request fails, the server returns a non-success status,
    /// or the body cannot be parsed as JSON.
    async fn get_api(
        &self,
        function: &str,
        email: &str,
        email_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let params = self.api_params(function, email, email_id);

        let headers = self.ajax_headers_no_ct();

        let response: serde_json::Value = self
            .http
            .get(self.ajax_url.as_str())
            .query(&params)
            .headers(headers)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(response)
    }

    async fn get_api_text(
        &self,
        function: &str,
        email: &str,
        email_id: Option<&str>,
    ) -> Result<String> {
        let params = self.api_params(function, email, email_id);

        let headers = self.ajax_headers_no_ct();

        let response = self
            .http
            .get(self.ajax_url.as_str())
            .query(&params)
            .headers(headers)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        Ok(response)
    }

    /// Extract the alias (local-part) from a full email address.
    ///
    /// If the string does not contain `@`, the full input is returned unchanged.
    fn extract_alias(email: &str) -> &str {
        email.split('@').next().unwrap_or(email)
    }

    fn api_params(
        &self,
        function: &str,
        email: &str,
        email_id: Option<&str>,
    ) -> Vec<(&str, String)> {
        let alias = Self::extract_alias(email);
        let timestamp = Self::timestamp();

        let mut params = vec![
            ("f", function.to_string()),
            ("site", "guerrillamail.com".to_string()),
            ("in", alias.to_string()),
            ("_", timestamp),
        ];

        if let Some(id) = email_id {
            params.insert(1, ("email_id", id.to_string()));
        }

        if function == "check_email" {
            params.insert(1, ("seq", "1".to_string()));
        }

        params
    }

    fn inbox_url(&self) -> String {
        self.base_url
            .join("inbox")
            .expect("constructing inbox URL should not fail")
            .into()
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

    fn ajax_headers(&self) -> HeaderMap {
        self.ajax_headers.clone()
    }

    fn ajax_headers_no_ct(&self) -> HeaderMap {
        self.ajax_headers_no_ct.clone()
    }

    fn base_headers(&self) -> HeaderMap {
        self.base_headers.clone()
    }
}

fn build_headers(
    url: &Url,
    user_agent: &str,
    api_token_header: &HeaderValue,
    include_content_type: bool,
) -> Result<HeaderMap> {
    let host = url.host_str().expect("validated url missing host");
    let host_port = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let origin = format!("{}://{}", url.scheme(), host_port);
    let referer = format!("{origin}/");

    let mut headers = HeaderMap::new();
    headers.insert(
        HOST,
        HeaderValue::from_str(&host_port).map_err(Error::HeaderValue)?,
    );
    let user_agent = HeaderValue::from_str(user_agent).map_err(Error::HeaderValue)?;
    headers.insert(USER_AGENT, user_agent);
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/json, text/javascript, */*; q=0.01"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
    if include_content_type {
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
    }
    headers.insert("Authorization", api_token_header.clone());
    headers.insert(
        "X-Requested-With",
        HeaderValue::from_static("XMLHttpRequest"),
    );
    headers.insert(ORIGIN, HeaderValue::from_str(&origin).map_err(Error::HeaderValue)?);
    headers.insert(REFERER, HeaderValue::from_str(&referer).map_err(Error::HeaderValue)?);
    headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
    headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
    headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-origin"));
    headers.insert("Priority", HeaderValue::from_static("u=0"));
    Ok(headers)
}

const BASE_URL: &str = "https://www.guerrillamail.com";
const AJAX_URL: &str = "https://www.guerrillamail.com/ajax.php";
const USER_AGENT_VALUE: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0";

/// Configures and bootstraps a GuerrillaMail [`Client`].
///
/// Conceptually, [`ClientBuilder`] holds request-layer options (proxy, TLS leniency, user agent,
/// endpoints, timeout). Calling [`build`](ClientBuilder::build) creates a `reqwest::Client` with
/// cookie storage enabled, fetches the GuerrillaMail homepage once, and captures the `ApiToken …`
/// header needed for all later AJAX calls.
///
/// Invariants/internal behavior:
/// - The bootstrap fetch happens exactly once during `build`; the resulting token is baked into the
///   constructed [`Client`].
/// - Defaults favor easy testing: no proxy, `danger_accept_invalid_certs = true`, browser-like
///   user agent, 30s timeout, and the public GuerrillaMail endpoints.
/// - `Clone` is cheap and copies configuration only; it does not perform additional network I/O.
///
/// Typical lifecycle: start with [`Client::builder`], adjust options, call `build`, then discard
/// the builder. Reuse the built [`Client`] (or its cheap clones) across tasks.
///
/// # Example
/// ```rust,no_run
/// # use guerrillamail_client::Client;
/// # #[tokio::main]
/// # async fn main() -> Result<(), guerrillamail_client::Error> {
/// let client = Client::builder()
///     .proxy("http://127.0.0.1:8080")
///     .danger_accept_invalid_certs(false)
///     .user_agent("my-app/2.0")
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    proxy: Option<String>,
    danger_accept_invalid_certs: bool,
    user_agent: String,
    ajax_url: Url,
    base_url: Url,
    timeout: std::time::Duration,
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
            ajax_url: Url::parse(AJAX_URL).expect("default ajax url must be valid"),
            base_url: Url::parse(BASE_URL).expect("default base url must be valid"),
            // Keep requests from hanging indefinitely; 30s is a conservative, service-friendly default.
            timeout: std::time::Duration::from_secs(30),
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
        let parsed = Url::parse(&ajax_url.into()).expect("invalid ajax_url");
        if parsed.host_str().is_none() {
            panic!("invalid ajax_url: missing host");
        }
        self.ajax_url = parsed;
        self
    }

    /// Override the GuerrillaMail base URL.
    ///
    /// This is primarily useful for testing.
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        let parsed = Url::parse(&base_url.into()).expect("invalid base_url");
        if parsed.host_str().is_none() {
            panic!("invalid base_url: missing host");
        }
        self.base_url = parsed;
        self
    }

    /// Override the default request timeout.
    ///
    /// The timeout applies to the whole request (connect + read), matching
    /// [`reqwest::ClientBuilder::timeout`]. Defaults to 30 seconds.
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the [`Client`] by performing the GuerrillaMail bootstrap request.
    ///
    /// Constructs a `reqwest::Client` with cookie storage, applies the configured proxy/TLS/user
    /// agent/timeouts, sends one GET to the GuerrillaMail homepage, and extracts the `ApiToken …`
    /// header required for later AJAX calls.
    ///
    /// # Errors
    /// - Returns `Error::Request` for HTTP client build issues, bootstrap network failures, or non-2xx responses.
    /// - Returns `Error::TokenParse` when the API token cannot be found in the bootstrap HTML.
    /// - Returns `Error::HeaderValue` if the token cannot be encoded into the authorization header.
    /// Network-related failures are transient; token/header errors likely indicate a page layout change.
    ///
    /// # Network
    /// Issues one GET request to the configured `base_url`.
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
            .danger_accept_invalid_certs(self.danger_accept_invalid_certs)
            .timeout(self.timeout);

        if let Some(proxy_url) = &self.proxy {
            builder = builder.proxy(reqwest::Proxy::all(proxy_url)?);
        }

        // URLs are validated when set on the builder.
        let base_url = self.base_url;
        let ajax_url = self.ajax_url;

        // Enable cookie store to persist session between requests.
        let http = builder.cookie_store(true).build()?;

        // Fetch the main page to get API token.
        let response = http.get(base_url.as_str()).send().await?.text().await?;

        // Parse API token: api_token : 'xxxxxxxx'
        let token_re = Regex::new(r"api_token\s*:\s*'([^']+)'")?;
        let api_token = token_re
            .captures(&response)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or(Error::TokenParse)?;
        let api_token_header = HeaderValue::from_str(&format!("ApiToken {}", api_token))?;

        let ajax_headers =
            build_headers(&ajax_url, &self.user_agent, &api_token_header, true)?;
        let ajax_headers_no_ct =
            build_headers(&ajax_url, &self.user_agent, &api_token_header, false)?;
        let base_headers =
            build_headers(&base_url, &self.user_agent, &api_token_header, true)?;

        Ok(Client {
            http,
            api_token_header,
            proxy: self.proxy,
            user_agent: self.user_agent,
            ajax_url,
            base_url,
            ajax_headers,
            ajax_headers_no_ct,
            base_headers,
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
        let base_url = Url::parse(&base_url).expect("invalid base_url in test");
        let ajax_url = Url::parse(&ajax_url).expect("invalid ajax_url in test");
        let ajax_headers =
            build_headers(&ajax_url, USER_AGENT_VALUE, &api_token_header, true).expect("ajax headers");
        let ajax_headers_no_ct =
            build_headers(&ajax_url, USER_AGENT_VALUE, &api_token_header, false).expect("ajax headers no ct");
        let base_headers =
            build_headers(&base_url, USER_AGENT_VALUE, &api_token_header, true).expect("base headers");
        Self {
            http,
            api_token_header,
            proxy: None,
            user_agent: USER_AGENT_VALUE.to_string(),
            ajax_url,
            base_url,
            ajax_headers,
            ajax_headers_no_ct,
            base_headers,
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
                "mail_id": "123",
                "mail_from": "sender@example.com",
                "mail_subject": "Subject",
                "mail_body": "<p>Body</p>",
                "mail_timestamp": "1700000000",
                "att": 1,
                "att_info": [{ "f": "file.txt", "t": "text/plain", "p": "99" }],
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

        let client = Client::new_for_tests(
            base_url.clone(),
            format!("{base_url}/ajax.php"),
        );

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
    async fn delete_email_returns_true_on_success() {
        let server = MockServer::start();
        let base_url = server.base_url();

        let delete_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/ajax.php")
                .query_param("f", "forget_me");
            then.status(204);
        });

        let client = Client::new_for_tests(
            base_url.clone(),
            format!("{base_url}/ajax.php"),
        );

        let ok = client.delete_email("alias@example.com").await.unwrap();

        assert!(ok);
        delete_mock.assert();
    }

    #[tokio::test]
    async fn delete_email_errors_on_non_success_status() {
        let server = MockServer::start();
        let base_url = server.base_url();

        let delete_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/ajax.php")
                .query_param("f", "forget_me");
            then.status(500);
        });

        let client = Client::new_for_tests(
            base_url.clone(),
            format!("{base_url}/ajax.php"),
        );

        let err = client.delete_email("alias@example.com").await.unwrap_err();

        assert!(matches!(err, Error::Request(_)));
        delete_mock.assert();
    }

    #[test]
    fn client_is_clone() {
        let base_url = "https://example.com";
        let client = Client::new_for_tests(
            base_url.to_string(),
            format!("{base_url}/ajax.php"),
        );

        let cloned = client.clone();

        assert_eq!(client.proxy, cloned.proxy);
        assert_eq!(client.user_agent, cloned.user_agent);
        assert_eq!(client.ajax_url, cloned.ajax_url);
        assert_eq!(client.base_url, cloned.base_url);
    }

    #[test]
    fn token_regex_accepts_broad_characters() {
        let token_re = Regex::new(r"api_token\s*:\s*'([^']+)'").unwrap();
        let sample = "const data = { api_token : 'abc-123.def:ghi' };";
        let caps = token_re.captures(sample).expect("should match");
        assert_eq!(caps.get(1).unwrap().as_str(), "abc-123.def:ghi");
    }
}
