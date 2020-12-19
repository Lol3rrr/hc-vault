#![warn(missing_docs)]
//! Async, highly concurrent crate to interact with vault and its mounts

/// The approle module is used for all interactions with the approle backend in vault
pub mod approle;
/// The Database module is used for all interactions with the database backend in vault
pub mod database;
/// The kv2 module is used for all interactions with the v2 key-value backend in vault
pub mod kv2;
/// The token module is used for all basic interactions with a simple client-token and no other
/// backend
pub mod token;

mod internals;

mod errors;

use serde::Serialize;
use url::Url;

pub use errors::Error;

/// This trait needs to be implemented by all auth backends to be used for
/// authenticating using that backend
pub trait Auth {
    /// Checking if the current session is expired and needs to be renewed or dropped
    ///
    /// Safety:
    /// This function is expected to be called from mulitple Threads at the same time
    /// in an unsychronized way, even while the Auth-Backend is in the middle of an
    /// Auth-Operation
    fn is_expired(&self) -> bool;
    /// Used to actually authenticate with the backend and obain a new valid session
    /// that can be used for further requests to vault
    ///
    /// Safety:
    /// This function is always called in a synchronized manner during which
    /// no other Thread is readinh the Token. This allows for optimizations and
    /// techniques to be used that rely on exclusive access to the Token when it
    /// is being updated, but not while reading it. This helps to avoid any
    /// Mutexes/Locks in the Auth-Backend.
    fn auth(&self, vault_url: &str) -> Result<(), Error>;
    /// Returns the vault token that can be used to make requests to vault
    /// as the current session
    ///
    /// Safety:
    /// This function is expected to be called from mulitple Threads at the same
    /// time in an unsychronized way, but not while the Backend is doing a single
    /// Auth-Operation
    fn get_token(&self) -> String;
}

/// The RenewPolicy describes how the vault client should deal with expired
/// vault session
pub enum RenewPolicy {
    /// Reauth causes the vault client to acquire a completly new vault session, via the
    /// provided auth config, if the old one expired. This is a lazy operation,
    /// so it only checks if it needs a new session before making a request
    Reauth,
    /// Nothing does nothing when the session expires. This will cause the client to always
    /// return a SessionExpired error when trying to request anything from vault
    Nothing,
}

/// The Configuration for the vault client
pub struct Config {
    /// The URL the client should use to connect to the vault instance
    pub vault_url: String,
    /// The Policy the client should use to handle sessions expiring
    ///
    /// Default: RenewPolicy::Reauth
    pub renew_policy: RenewPolicy,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            vault_url: "http://localhost:8200".to_string(),
            renew_policy: RenewPolicy::Reauth,
        }
    }
}

/// The Client struct represents a single Vault-Connection/Session that can be used for any
/// further requests to vault
pub struct Client<T: Auth> {
    config: Config,
    auth: T,
    reauth_mutex: std::sync::Mutex<()>,
}

impl<T: Auth> Client<T> {
    /// This function is used to obtain a new vault session with the given config and
    /// auth settings
    pub fn new(conf: Config, auth_opts: T) -> Result<Client<T>, Error> {
        match auth_opts.auth(&conf.vault_url) {
            Err(e) => return Err(e),
            Ok(()) => {}
        };

        Ok(Client::<T> {
            config: conf,
            auth: auth_opts,
            reauth_mutex: std::sync::Mutex::new(()),
        })
    }

    /// A simple method to get the underlying vault session/client token
    /// for the current vault session.
    /// It is not recommended to use this function, but rather stick to other
    /// more integrated parts, like the vault_request function
    pub fn get_token(&self) -> String {
        self.auth.get_token()
    }

    /// This function is used to check if the current
    /// session is still valid and if not to renew
    /// the session/obtain a new one and update
    /// all data related to it
    pub async fn check_session(&self) -> Result<(), Error> {
        if !self.auth.is_expired() {
            return Ok(());
        }

        // Take mutex to ensure only one thread can try to reauth at a time
        let _data = self.reauth_mutex.lock().unwrap();
        // If the mutex is acquired, check if the session still needs to be renewed or if another
        // thread has already done this, in which case this one should just return as its all fine
        // now
        if !self.auth.is_expired() {
            return Ok(());
        }

        let result = match self.config.renew_policy {
            RenewPolicy::Reauth => self.auth.auth(&self.config.vault_url),
            RenewPolicy::Nothing => Err(Error::SessionExpired),
        };

        return result;
    }

    /// This function is a general way to directly make requests to vault using
    /// the current session. This can be used to make custom requests or to make requests
    /// to mounts that are not directly covered by this crate.
    pub async fn vault_request<P: Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&P>,
    ) -> Result<reqwest::Response, Error> {
        self.check_session().await?;

        let mut url = match Url::parse(&self.config.vault_url) {
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

        let token = self.auth.get_token();

        let http_client = reqwest::Client::new();
        let mut req = http_client
            .request(method, url)
            .header("X-Vault-Token", &token)
            .header("X-Vault-Request", "true");

        if body.is_some() {
            req = req.json(body.unwrap());
        }

        let resp = match req.send().await {
            Err(e) => return Err(Error::from(e)),
            Ok(resp) => resp,
        };

        let status_code = resp.status().as_u16();

        match status_code {
            200 | 204 => Ok(resp),
            _ => Err(Error::from(status_code)),
        }
    }
}
