#![warn(missing_docs)]
//! A simple async library to interact with vault and its mounts

/// The approle module is used for all interactions with the approle backend in vault
pub mod approle;
/// The Database module is used for all interactions with the database backend in vault
pub mod database;
/// The kv2 module is used for all interactions with the v2 key-value backend in vault
pub mod kv2;

use serde::Serialize;
use std::fmt;
use std::time::{Duration, Instant};
use url::Url;

/// The Error
#[derive(Debug)]
pub enum Error {
    /// ParseError is returned when there was an error parsing a url
    ParseError(url::ParseError),
    /// ReqwestError is returned when the request made to vault itself fails
    ReqwestError(reqwest::Error),
    /// NotFound is returned when the given vault endpoint/path was not found on the
    /// actual vault instance that you are connected to
    NotFound,
    /// Unauthorized is returned when your current Session has either expired and has not
    /// been renewed or when the credentials for login are not valid and therefore rejected
    /// or when you try to access something that you dont have the permissions to do so
    Unauthorized,
    /// Other simply represents all other errors that could not be grouped into on the other
    /// categories listed above
    Other,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ParseError(ref cause) => write!(f, "Parse Error: {}", cause),
            Error::ReqwestError(ref cause) => write!(f, "Reqwest Error: {}", cause),
            Error::NotFound => write!(f, "Not Found"),
            Error::Unauthorized => write!(f, "Unauthorized"),
            Error::Other => write!(f, "Unknown error"),
        }
    }
}

impl From<url::ParseError> for Error {
    fn from(cause: url::ParseError) -> Error {
        Error::ParseError(cause)
    }
}
impl From<reqwest::Error> for Error {
    fn from(cause: reqwest::Error) -> Error {
        Error::ReqwestError(cause)
    }
}

enum AuthType {
    Approle,
    Token,
}

/// The Client struct represents a single Vault-Connection/Session that can be used for any
/// further requests to vault
pub struct Client {
    vault_url: String,
    auth_type: AuthType,
    approle: Option<approle::ApproleLogin>,

    token: String,
    token_start: Instant,
    token_duration: Duration,
}

impl Client {
    /// This function is used to obtain a new vault session using the given approle
    /// credentials
    pub async fn new_approle(
        vault_url: String,
        role_id: String,
        secret_id: String,
    ) -> Result<Client, Error> {
        let approle = approle::ApproleLogin { role_id, secret_id };

        let auth_res = match approle::authenticate(&vault_url, &approle).await {
            Err(e) => return Err(e),
            Ok(s) => s,
        };

        Ok(Client {
            vault_url,
            auth_type: AuthType::Approle,
            approle: Some(approle),
            token: auth_res.auth.client_token,
            token_start: Instant::now(),
            token_duration: Duration::from_secs(auth_res.auth.lease_duration),
        })
    }

    /// This function is used to obtain a new vault session that uses the given token
    /// as the authorization token when making requests to vault, the duration represents
    /// how long the token is valid
    pub async fn new_token(
        vault_url: String,
        token: String,
        duration: u64,
    ) -> Result<Client, Error> {
        Ok(Client {
            vault_url,
            auth_type: AuthType::Token,
            approle: None,
            token,
            token_start: Instant::now(),
            token_duration: Duration::from_secs(duration),
        })
    }

    /// Checks if the current session is expired.
    ///
    /// NOTE: This only checks for the duration to be expired and does not
    /// actually check if the session has been revoked by vault
    pub fn is_expired(&self) -> bool {
        self.token_start.elapsed() >= self.token_duration
    }

    async fn check_session(&mut self) {
        if !self.is_expired() {
            return;
        }

        match self.auth_type {
            AuthType::Approle => {
                let auth =
                    match approle::authenticate(&self.vault_url, self.approle.as_ref().unwrap())
                        .await
                    {
                        Err(e) => {
                            println!("Getting new Approle-Session: {}", e);
                            return;
                        }
                        Ok(n) => n,
                    };

                self.token = auth.auth.client_token;
                self.token_start = Instant::now();
                self.token_duration = Duration::from_secs(auth.auth.lease_duration);
            }
            AuthType::Token => {
                println!("Cant renew raw token session");
            }
        }
    }

    /// This function is a general way to directly make requests to vault using
    /// the current session. This can be used to make custom requests or to make requests
    /// to mounts that are not directly covered by this crate.
    pub async fn vault_request<T: Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response, Error> {
        let mut url = match Url::parse(&self.vault_url) {
            Err(e) => {
                return Err(Error::from(e));
            }
            Ok(url) => url,
        };
        url = match url.join("v1/") {
            Err(e) => {
                return Err(Error::from(e));
            }
            Ok(u) => u,
        };
        url = match url.join(path) {
            Err(e) => {
                return Err(Error::from(e));
            }
            Ok(u) => u,
        };

        let http_client = reqwest::Client::new();
        let mut req = http_client
            .request(method, url)
            .header("X-Vault-Token", &self.token);

        if body.is_some() {
            req = req.json(body.unwrap());
        }

        let resp = match req.send().await {
            Err(e) => return Err(Error::from(e)),
            Ok(resp) => resp,
        };

        let status_code = resp.status().as_u16();

        match status_code {
            200 => Ok(resp),
            401 | 403 => Err(Error::Unauthorized),
            404 => Err(Error::NotFound),
            _ => Err(Error::Other),
        }
    }
}
