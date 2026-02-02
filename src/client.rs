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

use crate::{Error, Message, Result};
use regex::Regex;
use reqwest::header::{
    ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, HOST, HeaderMap, HeaderValue, ORIGIN, REFERER,
    USER_AGENT,
};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Async client for the GuerrillaMail temporary email service.
///
/// A `Client` is cheap to clone at the `reqwest` level (internally shared connection pool),
/// but this type itself is not `Clone` in this implementation. Create it once and reuse it.
///
/// Construction requires a bootstrap request to GuerrillaMail in order to extract the
/// per-session API token from the homepage HTML. See [`Client::new`] and [`Client::builder`].
///
/// # Notes
/// - GuerrillaMail addresses are represented by an *alias* (the part before `@`) plus a domain.
///   Several API calls only use the alias; this client extracts it automatically.
/// - All methods are async and require a Tokio runtime (or any runtime compatible with `reqwest`).
pub struct Client {
    http: reqwest::Client,
    api_token_header: HeaderValue,
    proxy: Option<String>,
    user_agent: String,
    ajax_url: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("http", &"<reqwest::Client>")
            .field("api_token_header", &"<redacted>")
            .field("proxy", &self.proxy)
            .field("user_agent", &self.user_agent)
            .field("ajax_url", &self.ajax_url)
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
        let params = [("f", "set_email_user")];
        let form = [
            ("email_user", alias),
            ("lang", "en"),
            ("site", "guerrillamail.com"),
            ("in", " Set cancel"),
        ];

        let response: serde_json::Value = self
            .http
            .post(&self.ajax_url)
            .query(&params)
            .form(&form)
            .headers(self.headers())
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
        let response = self.get_api("fetch_email", email, Some(mail_id)).await?;
        let details: crate::EmailDetails = serde_json::from_value(response)?;
        Ok(details)
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
    /// `true` if the HTTP request succeeded (2xx status), otherwise `false`.
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
            .post(&self.ajax_url)
            .query(&params)
            .form(&form)
            .headers(self.headers())
            .send()
            .await?;

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

        let mut headers = self.headers();
        headers.remove(CONTENT_TYPE);

        let response: serde_json::Value = self
            .http
            .get(&self.ajax_url)
            .query(&params)
            .headers(headers)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(response)
    }

    /// Extract the alias (local-part) from a full email address.
    ///
    /// If the string does not contain `@`, the full input is returned unchanged.
    fn extract_alias(email: &str) -> &str {
        email.split('@').next().unwrap_or(email)
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
        headers.insert(HOST, HeaderValue::from_static("www.guerrillamail.com"));
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
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://www.guerrillamail.com"),
        );
        headers.insert(
            REFERER,
            HeaderValue::from_static("https://www.guerrillamail.com/"),
        );
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-origin"));
        headers.insert("Priority", HeaderValue::from_static("u=0"));
        headers
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
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    proxy: Option<String>,
    danger_accept_invalid_certs: bool,
    user_agent: String,
    ajax_url: String,
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

        // Enable cookie store to persist session between requests.
        let http = builder.cookie_store(true).build()?;

        // Fetch the main page to get API token.
        let response = http.get(BASE_URL).send().await?.text().await?;

        // Parse API token: api_token : 'xxxxxxxx'
        let token_re = Regex::new(r"api_token\s*:\s*'(\w+)'")?;
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
        })
    }
}
