extern crate hc_vault;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn valid_get_no_configuration() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    let resp_options = hc_vault::kv2::Configuration {
        max_versions: None,
        cas_required: None,
        delete_version_after: None,
    };

    let resp_body = json!({
        "data": resp_options,
    });

    Mock::given(method("GET"))
        .and(path("/v1/kv/config"))
        .and(header("X-Vault-Token", client_token))
        .respond_with(ResponseTemplate::new(200).set_body_json(&resp_body))
        .mount(&mock_server)
        .await;

    let auth =
        hc_vault::token::Session::new(client_token.to_string(), Duration::from_secs(120)).unwrap();
    let conf = hc_vault::Config {
        vault_url: mock_server.uri().clone(),
        ..Default::default()
    };
    let client = match hc_vault::Client::new(conf, auth) {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    match hc_vault::kv2::get_configuration(&client, "kv").await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
        }
        Ok(result) => {
            assert_eq!(result, resp_options);
        }
    };
}

#[tokio::test]
async fn valid_get_all_configuration() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    let resp_options = hc_vault::kv2::Configuration {
        max_versions: Some(13),
        cas_required: Some(true),
        delete_version_after: Some("test".to_string()),
    };

    let resp_body = json!({
        "data": resp_options,
    });

    Mock::given(method("GET"))
        .and(path("/v1/kv/config"))
        .and(header("X-Vault-Token", client_token))
        .respond_with(ResponseTemplate::new(200).set_body_json(&resp_body))
        .mount(&mock_server)
        .await;

    let auth =
        hc_vault::token::Session::new(client_token.to_string(), Duration::from_secs(120)).unwrap();
    let conf = hc_vault::Config {
        vault_url: mock_server.uri().clone(),
        ..Default::default()
    };
    let client = match hc_vault::Client::new(conf, auth) {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    match hc_vault::kv2::get_configuration(&client, "kv").await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
        }
        Ok(result) => {
            assert_eq!(result, resp_options);
        }
    };
}
