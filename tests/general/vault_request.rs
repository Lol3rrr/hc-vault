extern crate hc_vault;

use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde_json::json;

#[tokio::test]
async fn valid_vault_request_no_body() {
    let mock_server = MockServer::start().await;

    let req_method = reqwest::Method::GET;
    let req_path = "test/nice";

    let response = ResponseTemplate::new(200);

    Mock::given(method("GET"))
        .and(path("/v1/test/nice"))
        .and(header("X-Vault-Token", "testToken"))
        .and(header("X-Vault-Request", "true"))
        .respond_with(response)
        .mount(&mock_server)
        .await;

    let mut client =
        match hc_vault::Client::new_token(mock_server.uri(), "testToken".to_string(), 120).await {
            Err(e) => {
                assert!(false, "Should not return error: {}", e);
                return;
            }
            Ok(c) => c,
        };

    match client
        .vault_request::<String>(req_method, req_path, None)
        .await
    {
        Err(e) => {
            assert!(false, "Should not return error: {}", e);
        }
        Ok(_) => {
            assert!(true);
        }
    };
}

#[tokio::test]
async fn valid_vault_request_with_body() {
    let mock_server = MockServer::start().await;

    let req_method = reqwest::Method::POST;
    let req_path = "test/nice";

    let req_body = json!({
        "testKey": "testValue",
    });

    let response = ResponseTemplate::new(200);

    Mock::given(method("POST"))
        .and(path("/v1/test/nice"))
        .and(header("X-Vault-Token", "testToken"))
        .and(header("X-Vault-Request", "true"))
        .and(body_json(&req_body))
        .respond_with(response)
        .mount(&mock_server)
        .await;

    let mut client =
        match hc_vault::Client::new_token(mock_server.uri(), "testToken".to_string(), 120).await {
            Err(e) => {
                assert!(false, "Should not return error: {}", e);
                return;
            }
            Ok(c) => c,
        };

    match client
        .vault_request(req_method, req_path, Some(&req_body))
        .await
    {
        Err(e) => {
            assert!(false, "Should not return error: {}", e);
        }
        Ok(_) => {
            assert!(true);
        }
    };
}
