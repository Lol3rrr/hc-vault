use crate::Client;
use crate::Error;

use std::time::Duration;

use serde::Deserialize;

#[derive(Deserialize)]
struct DBCreds {
    username: String,
    password: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct DBCredsResponse {
    lease_id: String,
    lease_duration: u64,
    renewable: bool,
    data: DBCreds,
}

/// This struct holds Database Credentials returned by vault
#[derive(Debug)]
pub struct DatabaseCreds {
    /// The username to use when logging in to the database
    pub username: String,
    /// The password to use when logging in to the database
    pub password: String,
    /// The duration for which these credentials are valid for
    pub duration: Duration,
}

impl PartialEq for DatabaseCreds {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username
            && self.password == other.password
            && self.duration == other.duration
    }
}

/// This function is used to actually load the Database credentials from vault
pub async fn get_credentials(client: &mut Client, name: &str) -> Result<DatabaseCreds, Error> {
    client.check_session().await;

    let path = format!("database/creds/{}", name);
    let response = match client
        .vault_request::<String>(reqwest::Method::GET, &path, None)
        .await
    {
        Err(e) => return Err(e),
        Ok(res) => res,
    };

    let resp_body = match response.json::<DBCredsResponse>().await {
        Err(e) => return Err(Error::from(e)),
        Ok(body) => body,
    };

    Ok(DatabaseCreds {
        username: resp_body.data.username,
        password: resp_body.data.password,
        duration: Duration::from_secs(resp_body.lease_duration),
    })
}
