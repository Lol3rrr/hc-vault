use crate::Auth;
use crate::Client;
use crate::Error;

use serde::Serialize;

#[derive(Serialize)]
struct UndeleteVersionsBody {
    versions: Vec<u32>,
}

/// This undeletes previously deleted versions, not destroyed versions. These
/// versions will afterwards appear normally in any further requests as if they
/// have never been deleted in the first place
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/secret/kv/kv-v2#undelete-secret-versions)
pub async fn undelete_versions(
    client: &Client<impl Auth>,
    mount: &str,
    name: &str,
    versions: Vec<u32>,
) -> Result<(), Error> {
    let path = format!("{}/undelete/{}", mount, name);

    let req_body = UndeleteVersionsBody { versions };

    match client
        .vault_request::<UndeleteVersionsBody>(reqwest::Method::POST, &path, Some(&req_body))
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}
