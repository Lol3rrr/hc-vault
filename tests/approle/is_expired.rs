extern crate hc_vault;

use async_std::task;

use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde::Serialize;
use serde_json::json;

use hc_vault::Auth as AuthTrait;

#[derive(Serialize)]
struct ApproleAuthResponse {
    renewable: bool,
    lease_duration: u64,
    token_policies: Vec<String>,
    accessor: String,
    client_token: String,
}

#[derive(Serialize)]
struct ApproleResponse {
    auth: ApproleAuthResponse,
    lease_duration: u64,
    renewable: bool,
    lease_id: String,
}

#[test]
fn is_expired_true() {
    let mock_server = task::block_on(MockServer::start());

    let test_role_id = "testID".to_string();
    let test_secret_id = "testSecret".to_string();

    let expected_body = json!({
        "role_id": test_role_id.clone(),
        "secret_id": test_secret_id.clone(),
    });

    let response_body = ApproleResponse {
        auth: ApproleAuthResponse {
            renewable: true,
            lease_duration: 1,
            token_policies: vec!["test".to_string()],
            accessor: "testAccessor".to_string(),
            client_token: "testToken".to_string(),
        },
        lease_duration: 0,
        renewable: false,
        lease_id: "".to_string(),
    };
    let mut response = ResponseTemplate::new(200);
    response = response.set_body_json(response_body);

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .and(body_json(&expected_body))
            .respond_with(response)
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

    std::thread::sleep(std::time::Duration::from_secs(3));

    assert_eq!(true, tmp_auth.is_expired())
}
