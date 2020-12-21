extern crate hc_vault;

use async_std::task;

use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde_json::json;

use hc_vault::Auth as AuthTrait;

#[test]
fn valid_renew() {
    let mock_server = task::block_on(MockServer::start());

    let test_role_id = "testID".to_string();
    let test_secret_id = "testSecret".to_string();

    let expected_body = json!({
        "role_id": test_role_id.clone(),
        "secret_id": test_secret_id.clone(),
    });

    let response_body = json!({
        "auth": {
            "renewable": true,
            "lease_duration": 10,
            "token_policies": vec!["test".to_string()],
            "accessor": "testAccessor".to_string(),
            "client_token": "testToken".to_string(),
        },
        "lease_duration": 0,
        "renewable": false,
        "lease_id": "".to_string(),
    });
    let mut response = ResponseTemplate::new(200);
    response = response.set_body_json(response_body);

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .and(body_json(&expected_body))
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

    let tmp_auth = match hc_vault::approle::Session::new(test_role_id, test_secret_id) {
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
