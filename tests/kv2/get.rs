extern crate hc_vault;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize)]
struct KV2ResponseData<T> {
    data: T,
}

#[derive(Serialize)]
struct KV2Response<T> {
    data: KV2ResponseData<T>,
}

#[derive(Deserialize, Serialize, Debug)]
struct KV2Data {
    field1: String,
    field2: i64,
}

impl PartialEq for KV2Data {
    fn eq(&self, other: &Self) -> bool {
        self.field1 == other.field1 && self.field2 == other.field2
    }
}

#[tokio::test]
async fn valid_get() {
    let mock_server = MockServer::start().await;

    let client_token = "testToken";

    let kv_response_body = KV2Response {
        data: KV2ResponseData {
            data: KV2Data {
                field1: "testData".to_string(),
                field2: 123,
            },
        },
    };

    Mock::given(method("GET"))
        .and(path("/v1/kv/data/test"))
        .and(header("X-Vault-Token", client_token))
        .respond_with(ResponseTemplate::new(200).set_body_json(&kv_response_body))
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

    let data: KV2Data = match hc_vault::kv2::get(&client, "kv", "test").await {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    assert_eq!(data, kv_response_body.data.data);
}
