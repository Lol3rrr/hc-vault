use crate::Auth;
use crate::Client;
use crate::Error;

use serde::Serialize;

#[derive(Serialize)]
struct DeleteVersionsBody {
    versions: Vec<u32>,
}

/// Issues a soft delete, similiar to the delete function, for all the given
/// versions
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/secret/kv/kv-v2#delete-secret-versions)
pub async fn delete_versions(
    client: &Client<impl Auth>,
    mount: &str,
    name: &str,
    versions: Vec<u32>,
) -> Result<(), Error> {
    let path = format!("{}/delete/{}", mount, name);

    let req_body = DeleteVersionsBody { versions };

    match client
        .vault_request::<DeleteVersionsBody>(reqwest::Method::POST, &path, Some(&req_body))
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}
