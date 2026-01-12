//! GuerrillaMail async client implementation.

use crate::{Error, Message, Result};
use rand::seq::IndexedRandom;
use regex::Regex;
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, HOST, ORIGIN, REFERER,
    USER_AGENT,
};
use std::time::{SystemTime, UNIX_EPOCH};

const BASE_URL: &str = "https://www.guerrillamail.com";
const USER_AGENT_VALUE: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0";

/// Async client for GuerrillaMail temporary email service.
#[derive(Debug)]
pub struct Client {
    http: reqwest::Client,
    api_token: String,
    domains: Vec<String>,
    proxy: Option<String>,
}

impl Client {
    /// Create a new GuerrillaMail client.
    ///
    /// Connects to GuerrillaMail and retrieves the API token and available domains.
    pub async fn new() -> Result<Self> {
        Self::with_proxy(None).await
    }

    /// Create a new GuerrillaMail client with an optional proxy.
    ///
    /// # Arguments
    /// * `proxy` - Optional proxy URL (e.g., "http://127.0.0.1:8080")
    pub async fn with_proxy(proxy: Option<&str>) -> Result<Self> {
        let mut builder = reqwest::Client::builder().danger_accept_invalid_certs(true);

        if let Some(proxy_url) = proxy {
            builder = builder.proxy(reqwest::Proxy::all(proxy_url)?);
        }

        let http = builder.build()?;

        // Fetch the main page to get API token and domains
        let response = http.get(BASE_URL).send().await?.text().await?;

        // Parse API token: api_token : 'xxxxxxxx'
        let token_re = Regex::new(r"api_token\s*:\s*'(\w+)'").unwrap();
        let api_token = token_re
            .captures(&response)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or(Error::TokenParse)?;

        // Parse domain list: <option value="domain.com">
        let domain_re = Regex::new(r#"<option value="([\w.]+)">"#).unwrap();
        let domains: Vec<String> = domain_re
            .captures_iter(&response)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();

        if domains.is_empty() {
            return Err(Error::DomainParse);
        }

        Ok(Self {
            http,
            api_token,
            domains,
            proxy: proxy.map(|s| s.to_string()),
        })
    }

    /// Get the list of available email domains.
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    /// Get the proxy URL if one was configured.
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
    }

    /// Create a temporary email address.
    ///
    /// # Arguments
    /// * `alias` - The email alias (part before @)
    /// * `domain` - Optional domain; if None, a random domain is chosen
    ///
    /// # Returns
    /// The full email address (e.g., "alias@guerrillamail.com")
    pub async fn create_email(&self, alias: &str, domain: Option<&str>) -> Result<String> {
        let selected_domain = match domain {
            Some(d) => d.to_string(),
            None => {
                let mut rng = rand::rng();
                self.domains
                    .choose(&mut rng)
                    .ok_or(Error::NoDomains)?
                    .clone()
            }
        };

        let params = [("f", "set_email_user")];
        let form = [
            ("email_user", alias),
            ("lang", "en"),
            ("site", "guerrillamail.com"),
            ("in", " Set cancel"),
        ];

        self.http
            .post(format!("{}/ajax.php", BASE_URL))
            .query(&params)
            .form(&form)
            .headers(self.headers())
            .send()
            .await?
            .error_for_status()?;

        Ok(format!("{}@{}", alias, selected_domain))
    }

    /// Get messages for an email address.
    ///
    /// # Arguments
    /// * `email` - The full email address
    ///
    /// # Returns
    /// A list of messages in the inbox
    pub async fn get_messages(&self, email: &str) -> Result<Vec<Message>> {
        let alias = email.split('@').next().unwrap_or(email);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let params = [
            ("f", "check_email"),
            ("seq", "1"),
            ("site", "guerrillamail.com"),
            ("in", alias),
            ("_", &timestamp.to_string()),
        ];

        let mut headers = self.headers();
        headers.remove(CONTENT_TYPE);

        let response: serde_json::Value = self
            .http
            .get(format!("{}/ajax.php", BASE_URL))
            .query(&params)
            .headers(headers)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        // Parse messages from the "list" field if present
        let messages = response
            .get("list")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| serde_json::from_value::<Message>(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();

        Ok(messages)
    }

    /// Delete/forget an email address.
    ///
    /// # Arguments
    /// * `email` - The full email address to delete
    ///
    /// # Returns
    /// `true` if deletion was successful
    pub async fn delete_email(&self, email: &str) -> Result<bool> {
        let alias = email.split('@').next().unwrap_or(email);

        let params = [("f", "forget_me")];
        let form = [("site", "guerrillamail.com"), ("in", alias)];

        let response = self
            .http
            .post(format!("{}/ajax.php", BASE_URL))
            .query(&params)
            .form(&form)
            .headers(self.headers())
            .send()
            .await?;

        Ok(response.status().is_success())
    }

    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("www.guerrillamail.com"));
        headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/javascript, */*; q=0.01"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("ApiToken {}", self.api_token)).unwrap(),
        );
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
