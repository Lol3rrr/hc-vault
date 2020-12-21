use crate::Auth;
use crate::Client;
use crate::Error;

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
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/secret/kv/kv-v2#configure-the-kv-engine)
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
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/secret/kv/kv-v2#read-kv-engine-configuration)
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
