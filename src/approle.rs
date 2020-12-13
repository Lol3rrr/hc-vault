use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use url::Url;

use crate::Auth as AuthTrait;
use crate::Client;
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
        //
        // Safety:
        // This should be save to do, because the token is only read when doing
        // an operation and for that to happen, the validity of the current session is
        // checked and if the token needs to be updated, which is the time where this
        // part could panic/crash, the whole crate does not read from the token until
        // the update is done and the lock held while performing said update is also
        // completed.
        // In Conclusion, this part will never be executed while the token is updated
        // because the entire operations part of this crate is blocked until the update
        // is done, so the token will never be read during an update
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
        if status_code != 200 && status_code != 204 {
            return Err(Error::from(status_code));
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
        // Safety 1: This is safe to do, because we are the only thread to modify this
        // piece of data and can therefor safely construct the Box from the raw pointer,
        // which we previously stored in there and that should be valid, and then drop
        // said value.
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

/// Struct used for configuring an Approle-Role, contains all the
/// options that are possible to set on said Role
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/auth/approle#create-update-approle)
#[derive(Debug, Serialize)]
pub struct ApproleOptions {
    /// If the `secret_id` is required to be present when logging in
    pub bind_secret_id: Option<bool>,
    /// Specifies blocks of IP-addresses that can use this role
    pub secret_id_bound_cidrs: Option<Vec<String>>,
    /// The Number of times a single Secret-ID can be used for login.
    /// 0 means unlimited
    pub secret_id_num_uses: Option<u64>,
    /// The TTL of a Secret-ID
    ///
    /// Example-Value: `30m`
    pub secret_id_ttl: Option<String>,
    /// If the Secret-IDs generated for this role should be cluster local.
    ///
    /// Can't be changed after the Role has been created
    pub enable_local_secret_ids: Option<bool>,
    /// The TTL of the generated Tokens in seconds
    pub token_ttl: Option<u64>,
    /// The maximum TTL of generated Tokens in seconds
    pub token_max_ttl: Option<u64>,
    /// The Policies assigned to the generated Tokens
    pub token_policies: Option<Vec<String>>,
    /// Specifies blocks of IP-addresses that can authenticate using this role
    /// and ties the tokens to these blocks as well
    pub token_bound_cidrs: Option<Vec<String>>,
    /// Sets an explicit maximum TTL after which every token will expire even
    /// if it was renewed before
    pub token_explicit_max_ttl: Option<u64>,
    /// If the `default` Policy should not be set generated tokens
    pub token_no_default_policy: Option<bool>,
    /// The maximum Number of uses per generated Token, in it's lifetime
    pub token_num_uses: Option<u64>,
    /// The Period, if any, of the Tokens
    pub token_period: Option<u64>,
    /// The Type of Token that should be generated
    pub token_type: Option<String>,
}

/// Used to create or update an Approle-Role with the given options
///
/// # Arguments:
/// * `client`: A valid vault-client session that is used to execute this request
/// * `name`: The Name of the Role to modify/create
/// * `opts`: The Options that should be applied to the role
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/auth/approle#create-update-approle)
pub async fn create_update(
    client: &Client<impl AuthTrait>,
    name: &str,
    opts: ApproleOptions,
) -> Result<(), Error> {
    let path = format!("auth/approle/role/{}", name);

    match client
        .vault_request(reqwest::Method::POST, &path, Some(&opts))
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}
