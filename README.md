# hc-vault
A rust library to interact with hashicorp vault

## Example
### Obtaining a new Session using approle-auth
```rust
let vault_url = "http://localhost:8200".to_string();
let role_id = "example-role-id".to_string();
let secret_id = "example-secret-id".to_string();

let vault_client = match hc_vault::Client::new_approle(vault_url, role_id, secret_id).await {
  Err(e) => {
    println!("{}", e);
    return;
  },
  Ok(c) => c,
};
// Use vault_client for whatever you need to do
```
