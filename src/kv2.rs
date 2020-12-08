use crate::Client;
use crate::Error;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct KV2ResponseData<T> {
    data: T,
}

#[derive(Deserialize)]
struct KV2Response<T> {
    data: KV2ResponseData<T>,
}

/// This function is used to load data from the kv2-mount in vault.
/// The data will be serialized into a struct from the provided type
pub async fn get<T: DeserializeOwned>(
    client: &mut Client,
    mount: &str,
    name: &str,
) -> Result<T, Error> {
    let path = format!("{}/data/{}", mount, name);
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

#[derive(Serialize, Debug)]
struct UpdateOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    cas: Option<u16>,
}

#[derive(Serialize, Debug)]
struct UpdatePayload<T> {
    data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<UpdateOptions>,
}

/// This function is used to update or set data for a given path
/// in the kv2-mount in vault
pub async fn update_set<T: Serialize>(
    client: &mut Client,
    mount: &str,
    name: &str,
    data: T,
    cas: Option<u16>,
) -> Result<(), Error> {
    let path = format!("{}/data/{}", mount, name);

    let mut payload = UpdatePayload::<T> {
        data,
        options: None,
    };
    if cas.is_some() {
        payload.options = Some(UpdateOptions { cas });
    }

    match client
        .vault_request::<UpdatePayload<T>>(reqwest::Method::POST, &path, Some(&payload))
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}
