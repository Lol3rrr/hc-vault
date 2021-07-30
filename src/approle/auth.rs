use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    internals::{self, utils},
    Auth as AuthTrait, Error,
};

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

#[derive(Deserialize)]
struct RenewAuth {
    /// Whether or not the auth-session is renewable
    pub renewable: bool,
    /// The duration for which this session is valid
    pub lease_duration: u64,
    /// The policies associated with this session/token
    pub policies: Vec<String>,
    /// The actual Token that will also be needed/used for further
    /// requests to vault to authenticate with this session
    pub client_token: String,
}

#[derive(Deserialize)]
struct RenewResponse {
    /// The new auth data after renewal
    pub auth: RenewAuth,
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
        let current_time = utils::now_timestamp();

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
        let login_url = Url::parse(vault_url)?.join("v1/auth/approle/login")?;

        let http_client = reqwest::blocking::Client::new();
        let response = http_client.post(login_url).json(&self.approle).send()?;

        let status_code = response.status().as_u16();
        if status_code != 200 && status_code != 204 {
            return Err(Error::from_status_code(status_code));
        }

        let data: ApproleResponse = response.json()?;

        let token = data.auth.client_token;
        let current_time = utils::now_timestamp();
        let duration = data.auth.lease_duration;

        // Safety:
        // This is safe to do, because we are the only thread to access the
        // token therefore updating it is safe
        self.token.set_token(token);

        self.token.set_renewable(data.auth.renewable);

        // Update the Times afterwards to make sure that no thread could see
        // these new valid times and try to read the token before the update
        // is actually done, as these Times basically work as an indicator if
        // the token can be accessed or not
        self.token.set_start(current_time);
        self.token.set_duration(duration);

        Ok(())
    }

    fn is_renewable(&self) -> bool {
        self.token.get_renewable()
    }

    fn get_total_duration(&self) -> u64 {
        self.token.get_duration()
    }

    fn renew(&self, vault_url: &str) -> Result<(), Error> {
        let renew_url = Url::parse(vault_url)?.join("v1/auth/token/renew-self")?;

        let http_client = reqwest::blocking::Client::new();
        let response = http_client
            .post(renew_url)
            .header("X-Vault-Token", self.token.get_token().unwrap())
            .send()?;

        let status_code = response.status().as_u16();
        if status_code != 200 && status_code != 204 {
            return Err(Error::from_status_code(status_code));
        }

        let data: RenewResponse = response.json()?;

        let current_time = utils::now_timestamp();
        let duration = data.auth.lease_duration;
        let renewable = data.auth.renewable;

        self.token.set_renewable(renewable);

        // The times should again be set at the end after everything else is done already
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
