use crate::Auth;
use crate::Client;
use crate::Error;

use serde::de::DeserializeOwned;
use serde::Deserialize;

#[derive(Deserialize)]
struct ResponseData<T> {
    data: T,
}

#[derive(Deserialize)]
struct KV2Response<T> {
    data: ResponseData<T>,
}

/// This function is used to load data from the kv2-mount in vault.
/// The data will be serialized into a struct from the provided type
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/secret/kv/kv-v2#read-secret-version)
pub async fn get<T: DeserializeOwned>(
    client: &Client<impl Auth>,
    mount: &str,
    name: &str,
    version: Option<u32>,
) -> Result<T, Error> {
    let mut version_adding = "".to_string();
    if version.is_some() {
        version_adding = format!("?version={}", version.unwrap().to_string());
    }

    let path = format!("{}/data/{}{}", mount, name, &version_adding);
    let response = match client
        .vault_request::<String>(reqwest::Method::GET, &path, None)
        .await
    {
        Err(e) => return Err(e),
        Ok(r) => r,
    };

    let resp_body = match response.json::<KV2Response<T>>().await {
        Err(e) => {
            return Err(Error::from(e));
        }
        Ok(res) => res,
    };

    Ok(resp_body.data.data)
}
