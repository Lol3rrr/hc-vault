use crate::Auth;
use crate::Client;
use crate::Error;

/// This deletes the latest version of the secret, which only stops it from being
/// read/returned but currently doesnt actually delete the underlying data so it
/// can be undone using `undelete`
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/secret/kv/kv-v2#delete-latest-version-of-secret)
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
