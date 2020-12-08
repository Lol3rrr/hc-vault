use crate::Client;
use crate::Error;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Configuration describes the configuration for a single kv2-mount
#[derive(Serialize)]
pub struct Configuration {
    /// Whether or not all keys are required to have the 'cas' option
    /// set when updating/writing to them
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_required: Option<bool>,

    /// If set, this specifies the duration for which a version is held,
    /// older versions than described will be dropped
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_version_after: Option<String>,

    /// The Number of Versions that should be kept at any given time
    /// if this number is exceeded, the oldest versions are dropped
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_versions: Option<u32>,
}

/// This function is used to configure the given kv2-mount with the provided
/// configuration options
pub async fn configure(
    client: &mut Client,
    mount: &str,
    config: &Configuration,
) -> Result<(), Error> {
    let path = format!("{}/config", mount);

    match client
        .vault_request::<Configuration>(reqwest::Method::POST, &path, Some(config))
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}

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
