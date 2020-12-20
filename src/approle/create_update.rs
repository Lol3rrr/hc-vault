use serde::Serialize;

use crate::Auth;
use crate::Client;
use crate::Error;

/// Struct used for configuring an Approle-Role, contains all the
/// options that are possible to set on said Role
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/auth/approle#create-update-approle)
#[derive(Debug, Serialize)]
pub struct ApproleOptions {
    /// If the `secret_id` is required to be present when logging in
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_secret_id: Option<bool>,
    /// Specifies blocks of IP-addresses that can use this role
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id_bound_cidrs: Option<Vec<String>>,
    /// The Number of times a single Secret-ID can be used for login.
    /// 0 means unlimited
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id_num_uses: Option<u64>,
    /// The TTL of a Secret-ID
    ///
    /// Example-Value: `30m`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id_ttl: Option<String>,
    /// If the Secret-IDs generated for this role should be cluster local.
    ///
    /// Can't be changed after the Role has been created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_local_secret_ids: Option<bool>,
    /// The TTL of the generated Tokens in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<u64>,
    /// The maximum TTL of generated Tokens in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<u64>,
    /// The Policies assigned to the generated Tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_policies: Option<Vec<String>>,
    /// Specifies blocks of IP-addresses that can authenticate using this role
    /// and ties the tokens to these blocks as well
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_bound_cidrs: Option<Vec<String>>,
    /// Sets an explicit maximum TTL after which every token will expire even
    /// if it was renewed before
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_explicit_max_ttl: Option<u64>,
    /// If the `default` Policy should not be set generated tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_no_default_policy: Option<bool>,
    /// The maximum Number of uses per generated Token, in it's lifetime
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,
    /// The Period, if any, of the Tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_period: Option<u64>,
    /// The Type of Token that should be generated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

// TODO: Add test for this function
/// Used to create or update an Approle-Role with the given options
///
/// # Arguments:
/// * `client`: A valid vault-client session that is used to execute this request
/// * `name`: The Name of the Role to modify/create
/// * `opts`: The Options that should be applied to the role
///
/// [Vault-Documentation](https://www.vaultproject.io/api-docs/auth/approle#create-update-approle)
pub async fn create_update(
    client: &Client<impl Auth>,
    name: &str,
    opts: ApproleOptions,
) -> Result<(), Error> {
    let path = format!("auth/approle/role/{}", name);

    match client
        .vault_request(reqwest::Method::POST, &path, Some(&opts))
        .await
    {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}
