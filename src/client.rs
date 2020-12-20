use crate::Auth;
use crate::Config;
use crate::Error;
use crate::RenewPolicy;

use serde::Serialize;
use url::Url;

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
