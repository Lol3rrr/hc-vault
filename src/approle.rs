use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use url::Url;

use crate::internals;
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

    token: internals::TokenContainer,
}

impl AuthTrait for Session {
    fn is_expired(&self) -> bool {
        let start_time = self.token.get_start();
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let elapsed = current_time - start_time;
        let duration = self.token.get_duration();

        elapsed >= duration
    }
    fn get_token(&self) -> String {
        // Safety:
        // This Operation is indirectly synchronized, because the validity of
        // the session is checked before the Token is read and if the Token
        // needs to be updated, all further operations (including reading the
        // Token) are blocked until the Update of the Token is done.
        // Therefore the Token is never read while it is also being modified.
        match self.token.get_token() {
            None => String::from(""),
            Some(s) => s,
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

        // Safety:
        // This is safe to do, because we are the only thread to access the
        // token therefore updating it is safe
        self.token.set_token(token);

        // Update the Times afterwards to make sure that no thread could see
        // these new valid times and try to read the token before the update
        // is actually done, as these Times basically work as an indicator if
        // the token can be accessed or not
        self.token.set_start(current_time);
        self.token.set_duration(duration);

        Ok(())
    }
}

impl Session {
    /// This function returns a new Approle-Auth-Session that can be used
    /// as an authenticator for the vault client itself
    pub fn new(role_id: String, secret_id: String) -> Result<Session, Error> {
        let approle = ApproleLogin { role_id, secret_id };

        Ok(Session {
            approle,
            token: internals::TokenContainer::new(),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_secret_id: Option<bool>,
    /// Specifies blocks of IP-addresses that can use this role
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id_bound_cidrs: Option<Vec<String>>,
    /// The Number of times a single Secret-ID can be used for login.
    /// 0 means unlimited
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id_num_uses: Option<u64>,
    /// The TTL of a Secret-ID
    ///
    /// Example-Value: `30m`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id_ttl: Option<String>,
    /// If the Secret-IDs generated for this role should be cluster local.
    ///
    /// Can't be changed after the Role has been created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_local_secret_ids: Option<bool>,
    /// The TTL of the generated Tokens in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<u64>,
    /// The maximum TTL of generated Tokens in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<u64>,
    /// The Policies assigned to the generated Tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    /// Specifies blocks of IP-addresses that can authenticate using this role
    /// and ties the tokens to these blocks as well
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_bound_cidrs: Option<Vec<String>>,
    /// Sets an explicit maximum TTL after which every token will expire even
    /// if it was renewed before
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_explicit_max_ttl: Option<u64>,
    /// If the `default` Policy should not be set generated tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_no_default_policy: Option<bool>,
    /// The maximum Number of uses per generated Token, in it's lifetime
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,
    /// The Period, if any, of the Tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_period: Option<u64>,
    /// The Type of Token that should be generated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

// TODO: Add test for this function
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
