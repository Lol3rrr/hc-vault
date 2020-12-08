use serde::{Deserialize, Serialize};
use url::Url;

use crate::Error;

/// The Config for approle login
#[derive(Clone, Serialize)]
pub struct ApproleLogin {
    /// The role-id for the role to use
    pub role_id: String,
    /// The secret-it for the role
    pub secret_id: String,
}

/// The Auth part itself of the approle login response
#[allow(dead_code)]
#[derive(Deserialize)]
pub struct Auth {
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

/// The Response returned by vault for authorizing using approle
#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ApproleResponse {
    /// The actual auth content
    pub auth: Auth,
    /// The duration for which this lease is valid
    pub lease_duration: i64,
    /// Whether or not this lease is renewable
    pub renewable: bool,
    /// The id of this lease
    pub lease_id: String,
}

/// Used to login at vault with the given login/approle credentials
pub async fn authenticate(
    vault_url: &str,
    approle: &ApproleLogin,
) -> Result<ApproleResponse, Error> {
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

    let http_client = reqwest::Client::new();
    let res = http_client.post(login_url).json(&approle).send();

    let response = match res.await {
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

    match response.json::<ApproleResponse>().await {
        Err(e) => Err(Error::from(e)),
        Ok(json) => Ok(json),
    }
}
