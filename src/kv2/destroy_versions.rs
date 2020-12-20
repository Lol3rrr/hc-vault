use crate::Auth;
use crate::Client;
use crate::Error;

use serde::Serialize;

#[derive(Serialize)]
struct DestroyVersionsBody {
    versions: Vec<u32>,
}

/// Permanently removes/deletes the given versions with no way to recover
/// the data after this operation has completed
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/secret/kv/kv-v2#destroy-secret-versions)
pub async fn destroy_versions(
    client: &Client<impl Auth>,
    mount: &str,
    name: &str,
    versions: Vec<u32>,
) -> Result<(), Error> {
    let path = format!("{}/destroy/{}", mount, name);

    let req_body = DestroyVersionsBody { versions };

    match client
        .vault_request::<DestroyVersionsBody>(reqwest::Method::POST, &path, Some(&req_body))
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}
