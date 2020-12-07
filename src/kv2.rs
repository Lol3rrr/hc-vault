use crate::Client;
use crate::Error;

use serde::de::DeserializeOwned;
use serde::Deserialize;

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
    client.check_session().await;

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
