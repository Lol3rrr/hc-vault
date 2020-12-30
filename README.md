# hc-vault
A rust library to interact with hashicorp vault

## Introduction
This crate allows you to easily interact with Hashicorp's Vault, by giving you
easy to configure and use Auth-Methods and also having the most used Secret-Backends
already in the crate as modules, while also allowing for custom Requests to Vault for
currently not added Backends or custom Backends.

## Example
### Obtaining a new Session using approle-auth
```rust
let vault_url = "http://localhost:8200".to_string();
let role_id = "example-role-id".to_string();
let secret_id = "example-secret-id".to_string();

// Obtaining an Auth session, in this cause using approle
let approle_auth = match hc_vault::approle::Session::new(role_id, secret_id) {
	Err(e) => {
		println!("{}", e);
		return;
	},
	Ok(a) => a,
};

let config = hc_vault::Config {
	vault_url: vault_url, // The client will use this vault url
	..Default::default() // Use the default values for everything else
};

// Obtaining a valid vault-session, 
// using the previously obtained Auth Session and config
let vault_client = match hc_vault::Client::new(config, approle_auth).await {
  Err(e) => {
    println!("{}", e);
    return;
  },
  Ok(c) => c,
};
// Use vault_client for whatever you need to do
```
