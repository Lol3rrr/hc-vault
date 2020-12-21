extern crate hc_vault;

use async_std::task;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde_json::json;

#[test]
fn valid_renew_then_fail() {
    let mock_server = task::block_on(MockServer::start());

    let token = String::from("testToken");

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": {
                    "renewable": true,
                    "lease_duration": 10,
                    "token_policies": vec!["test"],
                    "accessor": "testAccessor",
                    "client_token": token.clone(),
                },
                "lease_duration": 0,
                "renewable": true,
                "lease_id": "",
            })))
            .mount(&mock_server),
    );

    let auth = hc_vault::approle::Session::new("test".to_string(), "test".to_string()).unwrap();

    let config = hc_vault::Config {
        vault_url: mock_server.uri(),
        renew_policy: hc_vault::RenewPolicy::Renew(0.75),
    };

    let client = hc_vault::Client::new(config, auth).unwrap();

    let response_body = json!({
        "auth": {
            "client_token": token.clone(),
            "policies": vec!["test"],
            "lease_duration": 10,
            "renewable": true,
        },
    });

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "testToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .up_to_n_times(1)
            .expect(1)
            .mount(&mock_server),
    );

    match client.renew_background() {
        Ok(_) => {
            assert!(true);
        }
        Err(e) => {
            if let hc_vault::RenewError::AuthError(_) = e {
                assert!(true);
                return;
            }

            assert!(false, "Should not return error: {}", e);
        }
    }
}

#[test]
fn renew_cant_renew() {
    let mock_server = task::block_on(MockServer::start());

    let token = String::from("testToken");

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": {
                    "renewable": false,
                    "lease_duration": 10,
                    "token_policies": vec!["test"],
                    "accessor": "testAccessor",
                    "client_token": token.clone(),
                },
                "lease_duration": 0,
                "renewable": true,
                "lease_id": "",
            })))
            .mount(&mock_server),
    );

    let auth = hc_vault::approle::Session::new("test".to_string(), "test".to_string()).unwrap();

    let config = hc_vault::Config {
        vault_url: mock_server.uri(),
        renew_policy: hc_vault::RenewPolicy::Renew(0.75),
    };

    let client = hc_vault::Client::new(config, auth).unwrap();

    match client.renew_background() {
        Ok(_) => {
            assert!(false);
        }
        Err(e) => {
            if let hc_vault::RenewError::NotRenewable = e {
                assert!(true);
                return;
            }

            assert!(false, "Wrong error returned: {}", e);
        }
    }
}

#[test]
fn renew_not_enabled() {
    let mock_server = task::block_on(MockServer::start());

    let token = String::from("testToken");

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": {
                    "renewable": false,
                    "lease_duration": 10,
                    "token_policies": vec!["test"],
                    "accessor": "testAccessor",
                    "client_token": token.clone(),
                },
                "lease_duration": 0,
                "renewable": true,
                "lease_id": "",
            })))
            .mount(&mock_server),
    );

    let auth = hc_vault::approle::Session::new("test".to_string(), "test".to_string()).unwrap();

    let config = hc_vault::Config {
        vault_url: mock_server.uri(),
        renew_policy: hc_vault::RenewPolicy::Nothing,
    };

    let client = hc_vault::Client::new(config, auth).unwrap();

    match client.renew_background() {
        Ok(_) => {
            assert!(false);
        }
        Err(e) => {
            if let hc_vault::RenewError::NotEnabled = e {
                assert!(true);
                return;
            }

            assert!(false, "Wrong error returned: {}", e);
        }
    }
}
