use crate::Auth;
use crate::Client;
use crate::Error;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Configuration describes the configuration for a single kv2-mount
#[derive(Serialize, Deserialize, Debug)]
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

impl PartialEq for Configuration {
    fn eq(&self, other: &Self) -> bool {
        self.cas_required == other.cas_required
            && self.delete_version_after == other.delete_version_after
            && self.max_versions == other.max_versions
    }
}

#[derive(Deserialize)]
struct ConfigurationResponse {
    data: Configuration,
}

/// This function is used to configure the given kv2-mount with the provided
/// configuration options
pub async fn configure(
    client: &Client<impl Auth>,
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

/// Is used to load the current configuration of the kv2-backend mounted
/// at the given mount point
pub async fn get_configuration(
    client: &Client<impl Auth>,
    mount: &str,
) -> Result<Configuration, Error> {
    let path = format!("{}/config", mount);

    let resp = match client
        .vault_request::<String>(reqwest::Method::GET, &path, None)
        .await
    {
        Err(e) => return Err(e),
        Ok(r) => r,
    };

    let resp_body = match resp.json::<ConfigurationResponse>().await {
        Err(e) => return Err(Error::from(e)),
        Ok(res) => res,
    };

    Ok(resp_body.data)
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
    client: &Client<impl Auth>,
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

/// This deletes the latest version of the secret, which only stops it from being
/// read/returned but currently doesnt actually delete the underlying data so it
/// can be undone using `undelete`
pub async fn delete(client: &Client<impl Auth>, mount: &str, name: &str) -> Result<(), Error> {
    let path = format!("{}/data/{}", mount, name);

    match client
        .vault_request::<String>(reqwest::Method::DELETE, &path, None)
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}

#[derive(Serialize)]
struct DeleteVersionsBody {
    versions: Vec<u32>,
}

/// Issues a soft delete, similiar to the delete function, for all the given
/// versions
pub async fn delete_versions(
    client: &Client<impl Auth>,
    mount: &str,
    name: &str,
    versions: Vec<u32>,
) -> Result<(), Error> {
    let path = format!("{}/delete/{}", mount, name);

    let req_body = DeleteVersionsBody { versions: versions };

    match client
        .vault_request::<DeleteVersionsBody>(reqwest::Method::POST, &path, Some(&req_body))
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}

#[derive(Serialize)]
struct UndeleteVersionsBody {
    versions: Vec<u32>,
}

/// This undeletes previously deleted versions, not destroyed versions. These
/// versions will afterwards appear normally in any further requests as if they
/// have never been deleted in the first place
pub async fn undelete_versions(
    client: &Client<impl Auth>,
    mount: &str,
    name: &str,
    versions: Vec<u32>,
) -> Result<(), Error> {
    let path = format!("{}/undelete/{}", mount, name);

    let req_body = UndeleteVersionsBody { versions: versions };

    match client
        .vault_request::<UndeleteVersionsBody>(reqwest::Method::POST, &path, Some(&req_body))
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}

#[derive(Serialize)]
struct DestroyVersionsBody {
    versions: Vec<u32>,
}

/// Permanently removes/deletes the given versions with no way to recover
/// the data after this operation has completed
pub async fn destroy_versions(
    client: &Client<impl Auth>,
    mount: &str,
    name: &str,
    versions: Vec<u32>,
) -> Result<(), Error> {
    let path = format!("{}/destroy/{}", mount, name);

    let req_body = DestroyVersionsBody { versions: versions };

    match client
        .vault_request::<DestroyVersionsBody>(reqwest::Method::POST, &path, Some(&req_body))
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}

/// This is used to delete all versions and metadata associated with a given
/// key in the kv-store. This operation is, like destroy_versions, permanent and
/// cannot be undone
pub async fn delete_metadata_all_versions(
    client: &Client<impl Auth>,
    mount: &str,
    name: &str,
) -> Result<(), Error> {
    let path = format!("{}/metadata/{}", mount, name);

    match client
        .vault_request::<String>(reqwest::Method::DELETE, &path, None)
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}

// TODO: Add List, Read Metadata, Update Metadata
