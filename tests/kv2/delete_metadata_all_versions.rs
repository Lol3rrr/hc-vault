extern crate hc_vault;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use std::time::Duration;

#[tokio::test]
async fn valid_delete_metadata_all_versions() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    Mock::given(method("DELETE"))
        .and(path("/v1/kv/metadata/test"))
        .and(header("X-Vault-Token", client_token))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
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

    match hc_vault::kv2::delete_metadata_all_versions(&client, "kv", "test").await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
        }
        Ok(_) => {
            assert!(true);
        }
    };
}
