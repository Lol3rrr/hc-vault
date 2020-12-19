extern crate hc_vault;

use async_std::task;

use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde_json::json;

use hc_vault::Auth as AuthTrait;

#[test]
fn valid_new_kubernetes() {
    let mock_server = task::block_on(MockServer::start());

    let test_role = "testRole".to_string();
    let test_jwt = "testJWT".to_string();

    let expected_body = json!({
        "role": test_role.clone(),
        "jwt": test_jwt.clone(),
    });

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
            .and(body_json(&expected_body))
            .respond_with(response)
            .mount(&mock_server),
    );

    let tmp_auth = match hc_vault::kubernetes::Session::new(test_role, test_jwt) {
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
}

#[test]
fn invalid_new_kubernetes_not_found() {
    let mock_server = task::block_on(MockServer::start());

    let test_role = "testRole".to_string();
    let test_jwt = "testJWT".to_string();

    let expected_body = json!({
        "role": test_role.clone(),
        "jwt": test_jwt.clone(),
    });

    let response = ResponseTemplate::new(404);

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/kubernetes/login"))
            .and(body_json(&expected_body))
            .respond_with(response)
            .mount(&mock_server),
    );

    let tmp_auth = match hc_vault::kubernetes::Session::new(test_role, test_jwt) {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    match tmp_auth.auth(&mock_server.uri()) {
        Err(_) => assert!(true),
        Ok(_) => assert!(false, "Should return error"),
    };
}

#[test]
fn invalid_new_kubernetes_not_valid_403() {
    let mock_server = task::block_on(MockServer::start());

    let test_role = "testRole".to_string();
    let test_jwt = "testJWT".to_string();

    let expected_body = json!({
        "role": test_role.clone(),
        "jwt": test_jwt.clone(),
    });

    let response = ResponseTemplate::new(403);

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/kubernetes/login"))
            .and(body_json(&expected_body))
            .respond_with(response)
            .mount(&mock_server),
    );

    let tmp_auth = match hc_vault::kubernetes::Session::new(test_role, test_jwt) {
        Err(e) => {
            assert!(false, "Should not return error: '{}'", e);
            return;
        }
        Ok(s) => s,
    };

    match tmp_auth.auth(&mock_server.uri()) {
        Err(_) => assert!(true),
        Ok(_) => assert!(false, "Should return error"),
    };
}
