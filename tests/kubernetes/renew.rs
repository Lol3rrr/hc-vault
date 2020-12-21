extern crate hc_vault;

use async_std::task;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde_json::json;

use hc_vault::Auth as AuthTrait;

#[test]
fn valid_renew() {
    let mock_server = task::block_on(MockServer::start());

    let response_body = json!({
        "auth": {
            "client_token": "testToken",
            "accessor": "testAccessor",
            "policies": ["test"],
            "metadata": {
                "role": "testRole",
                "service_account_name": "testName",
                "service_account_namespace": "testNamespace",
                "service_account_secret_name": "testSecretName",
                "service_account_uid": "testUID",
            },
            "lease_duration": 120,
            "renewable": true,
        },
    });

    let mut response = ResponseTemplate::new(200);
    response = response.set_body_json(response_body);

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/kubernetes/login"))
            .respond_with(response)
            .expect(1)
            .mount(&mock_server),
    );

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .and(header("X-Vault-Token", "testToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": {
                    "renewable": true,
                    "lease_duration": 120,
                    "policies": vec!["test".to_string()],
                    "client_token": "testToken".to_string(),
                },
            })))
            .expect(1)
            .mount(&mock_server),
    );

    let tmp_auth =
        match hc_vault::kubernetes::Session::new("testRole".to_string(), "testJWT".to_string()) {
            Err(e) => {
                assert!(false, "Should not return error: '{}'", e);
                return;
            }
            Ok(s) => s,
        };

    match tmp_auth.auth(&mock_server.uri()) {
        Err(e) => assert!(false, "Should not return error: '{}'", e),
        Ok(_) => assert!(true),
    };

    match tmp_auth.renew(&mock_server.uri()) {
        Err(e) => assert!(false, "Should not return error: '{}'", e),
        Ok(_) => assert!(true),
    }

    assert_eq!(tmp_auth.get_total_duration(), 120);
}
