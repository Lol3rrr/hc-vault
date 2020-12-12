use serde::{Deserialize, Serialize};
use std::time::{Instant, SystemTime};
use url::Url;

use crate::Auth as AuthTrait;
use crate::Error;

/// The Config for approle login
#[derive(Clone, Serialize)]
pub struct ApproleLogin {
    /// The role-id for the role to use
    pub role_id: String,
    /// The secret-it for the role
    pub secret_id: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct Auth {
    /// Whether or not the auth-session is renewable
    pub renewable: bool,
    /// The duration for which this session is valid
    pub lease_duration: u64,
    /// The policies associated with this session/token
    pub token_policies: Vec<String>,
    /// IDK
    pub accessor: String,
    /// The actual Token that will also be needed/used for further
    /// requests to vault to authenticate with this session
    pub client_token: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct ApproleResponse {
    /// The actual auth content
    pub auth: Auth,
    /// The duration for which this lease is valid
    pub lease_duration: i64,
    /// Whether or not this lease is renewable
    pub renewable: bool,
    /// The id of this lease
    pub lease_id: String,
}

/// The Auth session for the approle backend, used by the vault client itself
/// to authenticate using approle
pub struct Session {
    approle: ApproleLogin,

    token: std::sync::atomic::AtomicPtr<String>,
    /// The Start time in seconds
    token_start: std::sync::atomic::AtomicU64,
    /// The duration in seconds
    token_duration: std::sync::atomic::AtomicU64,
}

impl AuthTrait for Session {
    fn is_expired(&self) -> bool {
        let start_time = self.token_start.load(std::sync::atomic::Ordering::SeqCst);
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let elapsed = current_time - start_time;
        let duration = self
            .token_duration
            .load(std::sync::atomic::Ordering::SeqCst);

        elapsed >= duration
    }
    fn get_token(&self) -> String {
        // There could technically be a Ptr-Swap + Drop of the old value between loading
        // the address/value here and cloning it.
        // Right now I don't know how to fix this issue, but this also seems rather
        // unlikely as we don't hold the address of the old value but quickly
        // clone the data and then use that for any further work we might need to do
        let token = self.token.load(std::sync::atomic::Ordering::SeqCst);
        match unsafe { token.as_ref() } {
            None => String::from(""),
            Some(s) => s.clone(),
        }
    }
    fn auth(&self, vault_url: &str) -> Result<(), Error> {
        let mut login_url = match Url::parse(vault_url) {
            Err(e) => {
                return Err(Error::from(e));
            }
            Ok(url) => url,
        };
        login_url = match login_url.join("v1/auth/approle/login") {
            Err(e) => {
                return Err(Error::from(e));
            }
            Ok(u) => u,
        };

        let http_client = reqwest::blocking::Client::new();
        let res = http_client.post(login_url).json(&self.approle).send();

        let response = match res {
            Err(e) => {
                return Err(Error::from(e));
            }
            Ok(resp) => resp,
        };

        let status_code = response.status().as_u16();
        if status_code == 400 {
            return Err(Error::InvalidRequest);
        }
        if status_code == 403 {
            return Err(Error::Unauthorized);
        }
        if status_code == 404 {
            return Err(Error::NotFound);
        }
        if status_code == 503 {
            return Err(Error::IsSealed);
        }
        if status_code != 200 && status_code != 204 {
            return Err(Error::Other);
        }

        let data = match response.json::<ApproleResponse>() {
            Err(e) => Err(Error::from(e)),
            Ok(json) => Ok(json),
        };

        let data = data.unwrap();

        let token = data.auth.client_token;
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let duration = data.auth.lease_duration;

        let boxed_token = Box::new(token);

        let old_token_ptr = self.token.swap(
            Box::into_raw(boxed_token),
            std::sync::atomic::Ordering::SeqCst,
        );
        self.token_start
            .store(current_time, std::sync::atomic::Ordering::SeqCst);
        self.token_duration
            .store(duration, std::sync::atomic::Ordering::SeqCst);

        // This is used to actually drop the old value, but needs to be wrapped
        // in unsafe
        //
        // Safety: This is safe to do, because we are the only thread to modify this
        // piece of data and can therefor safely construct the Box from the raw pointer,
        // which we previously stored in there and that should be valid, and then drop
        // said value
        unsafe {
            drop(Box::from_raw(old_token_ptr));
        }

        Ok(())
    }
}

impl Session {
    /// This function returns a new Approle-Auth-Session that can be used
    /// as an authenticator for the vault client itself
    pub fn new(role_id: String, secret_id: String) -> Result<Session, Error> {
        let approle = ApproleLogin { role_id, secret_id };

        let boxed_token = Box::new(String::from(""));

        Ok(Session {
            approle,
            token: std::sync::atomic::AtomicPtr::new(Box::into_raw(boxed_token)),
            token_start: std::sync::atomic::AtomicU64::new(0),
            token_duration: std::sync::atomic::AtomicU64::new(0),
        })
    }
}
