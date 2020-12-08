extern crate hc_vault;

use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde_json::json;

#[tokio::test]
async fn valid_update_set_no_options() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    let req_data = json!({
        "testKey": "testValue"
    });

    let req_body = json!({
        "data": req_data,
    });

    Mock::given(method("POST"))
        .and(path("/v1/kv/data/test"))
        .and(header("X-Vault-Token", client_token))
        .and(body_json(&req_body))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let mut client =
        match hc_vault::Client::new_token(mock_server.uri().clone(), client_token.to_string(), 120)
            .await
        {
            Err(e) => {
                assert!(false, "Should not return error: '{}'", e);
                return;
            }
            Ok(s) => s,
        };

    match hc_vault::kv2::update_set(&mut client, "kv", "test", req_data.clone(), None).await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
        }
        Ok(_) => {
            assert!(true);
        }
    };
}
