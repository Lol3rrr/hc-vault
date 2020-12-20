use crate::Auth;
use crate::Client;
use crate::Error;

/// This is used to delete all versions and metadata associated with a given
/// key in the kv-store. This operation is, like destroy_versions, permanent and
/// cannot be undone
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/secret/kv/kv-v2#delete-metadata-and-all-versions)
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
