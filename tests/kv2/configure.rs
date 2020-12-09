extern crate hc_vault;

use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn valid_configure_no_options() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    let options = hc_vault::kv2::Configuration {
        max_versions: None,
        cas_required: None,
        delete_version_after: None,
    };

    let req_body = json!({});

    Mock::given(method("POST"))
        .and(path("/v1/kv/config"))
        .and(header("X-Vault-Token", client_token))
        .and(body_json(&req_body))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let auth =
        hc_vault::token::Session::new(client_token.to_string(), Duration::from_secs(120)).unwrap();
    let mut client = match hc_vault::Client::new(mock_server.uri().clone(), auth).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    match hc_vault::kv2::configure(&mut client, "kv", &options).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
        }
        Ok(_) => {
            assert!(true);
        }
    };
}

#[tokio::test]
async fn valid_configure_only_max_verison_option() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    let options = hc_vault::kv2::Configuration {
        max_versions: Some(13),
        cas_required: None,
        delete_version_after: None,
    };

    let req_body = json!({
        "max_versions": 13
    });

    Mock::given(method("POST"))
        .and(path("/v1/kv/config"))
        .and(header("X-Vault-Token", client_token))
        .and(body_json(&req_body))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let auth =
        hc_vault::token::Session::new(client_token.to_string(), Duration::from_secs(120)).unwrap();
    let mut client = match hc_vault::Client::new(mock_server.uri().clone(), auth).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    match hc_vault::kv2::configure(&mut client, "kv", &options).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
        }
        Ok(_) => {
            assert!(true);
        }
    };
}

#[tokio::test]
async fn valid_configure_only_cas_required_option() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    let options = hc_vault::kv2::Configuration {
        max_versions: None,
        cas_required: Some(true),
        delete_version_after: None,
    };

    let req_body = json!({
        "cas_required": true
    });

    Mock::given(method("POST"))
        .and(path("/v1/kv/config"))
        .and(header("X-Vault-Token", client_token))
        .and(body_json(&req_body))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let auth =
        hc_vault::token::Session::new(client_token.to_string(), Duration::from_secs(120)).unwrap();
    let mut client = match hc_vault::Client::new(mock_server.uri().clone(), auth).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    match hc_vault::kv2::configure(&mut client, "kv", &options).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
        }
        Ok(_) => {
            assert!(true);
        }
    };
}

#[tokio::test]
async fn valid_configure_only_delete_version_after_option() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    let options = hc_vault::kv2::Configuration {
        max_versions: None,
        cas_required: None,
        delete_version_after: Some("5s".to_string()),
    };

    let req_body = json!({
        "delete_version_after": "5s"
    });

    Mock::given(method("POST"))
        .and(path("/v1/kv/config"))
        .and(header("X-Vault-Token", client_token))
        .and(body_json(&req_body))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let auth =
        hc_vault::token::Session::new(client_token.to_string(), Duration::from_secs(120)).unwrap();
    let mut client = match hc_vault::Client::new(mock_server.uri().clone(), auth).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    match hc_vault::kv2::configure(&mut client, "kv", &options).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
        }
        Ok(_) => {
            assert!(true);
        }
    };
}

#[tokio::test]
async fn valid_configure_all_options() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    let options = hc_vault::kv2::Configuration {
        max_versions: Some(13),
        cas_required: Some(true),
        delete_version_after: Some("5s".to_string()),
    };

    let req_body = json!({
        "max_versions": 13,
        "cas_required": true,
        "delete_version_after": "5s".to_string(),
    });

    Mock::given(method("POST"))
        .and(path("/v1/kv/config"))
        .and(header("X-Vault-Token", client_token))
        .and(body_json(req_body))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let auth =
        hc_vault::token::Session::new(client_token.to_string(), Duration::from_secs(120)).unwrap();
    let mut client = match hc_vault::Client::new(mock_server.uri().clone(), auth).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    match hc_vault::kv2::configure(&mut client, "kv", &options).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
        }
        Ok(_) => {
            assert!(true);
        }
    };
}
