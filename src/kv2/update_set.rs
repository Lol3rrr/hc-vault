use crate::Auth;
use crate::Client;
use crate::Error;

use serde::Serialize;

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
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/secret/kv/kv-v2#create-update-secret)
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
