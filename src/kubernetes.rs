use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use url::Url;

use crate::internals;
use crate::Auth as AuthTrait;
use crate::Error;

/// The Config for Kubernetes Login
#[derive(Clone, Serialize)]
pub struct KubernetesLogin {
    /// The Role that you want to login as
    pub role: String,
    /// The JWT Token to use for authentication
    pub jwt: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct KubernetesMetadata {
    role: String,
    service_account_name: String,
    service_account_namespace: String,
    service_account_secret_name: String,
    service_account_uid: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct KubernetesAuth {
    client_token: String,
    accessor: String,
    policies: Vec<String>,
    metadata: KubernetesMetadata,
    lease_duration: u64,
    renewable: bool,
}

#[derive(Deserialize)]
struct KubernetesResponse {
    auth: KubernetesAuth,
}

/// The Auth session for the Kubernetes Backend, used by the vault client
/// to authenticate requests
pub struct Session {
    kubernetes: KubernetesLogin,
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
        // This is indirectly synchronized as this function is only called
        // while the session is not being updated and therefore the token
        // will not be changing while this function is being called
        match self.token.get_token() {
            None => String::from(""),
            Some(s) => s,
        }
    }

    fn auth(&self, vault_url: &str) -> Result<(), Error> {
        let mut login_url = match Url::parse(vault_url) {
            Err(e) => return Err(Error::from(e)),
            Ok(url) => url,
        };
        login_url = match login_url.join("v1/auth/kubernetes/login") {
            Err(e) => return Err(Error::from(e)),
            Ok(u) => u,
        };

        let http_client = reqwest::blocking::Client::new();
        let response = match http_client.post(login_url).json(&self.kubernetes).send() {
            Err(e) => return Err(Error::from(e)),
            Ok(resp) => resp,
        };

        let status_code = response.status().as_u16();
        if status_code != 200 && status_code != 204 {
            return Err(Error::from(status_code));
        }

        let data = match response.json::<KubernetesResponse>() {
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
        // This is safe to do, because we are the only thread accessing the
        // Token at that moment so we can perform the update without any other
        // means of synchronization
        self.token.set_token(token);

        // Update the Times afterwards, as they are basically acting like a switch
        // that once they are "valid" again, every thread can read the token
        // agai. So once they are set we have to assume that threads will
        // immediately try to access the token
        self.token.set_start(current_time);
        self.token.set_duration(duration);

        Ok(())
    }
}
