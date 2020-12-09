extern crate hc_vault;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde_json::json;

use std::time::Duration;

#[tokio::test]
async fn valid_get_credentials() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    let db_creds = hc_vault::database::DatabaseCreds {
        username: "test_username".to_string(),
        password: "test_password".to_string(),
        duration: Duration::from_secs(120),
    };

    let db_response_body = json!({
        "lease_id": "test_id",
        "lease_duration": 120,
        "renewable": true,
        "data": {
            "username": "test_username",
            "password": "test_password",
        },
    });

    Mock::given(method("GET"))
        .and(path("/v1/database/creds/test_db"))
        .and(header("X-Vault-Token", client_token))
        .respond_with(ResponseTemplate::new(200).set_body_json(&db_response_body))
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

    let data = match hc_vault::database::get_credentials(&mut client, "test_db").await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    assert_eq!(data, db_creds);
}
