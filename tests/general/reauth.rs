extern crate hc_vault;

use async_std::task;

use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use serde::Serialize;
use serde_json::json;

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
fn valid_auth_from_multiple_threads() {
    let mock_server = task::block_on(MockServer::start());

    let test_role_id = "testID".to_string();
    let test_secret_id = "testSecret".to_string();

    let expected_body = json!({
        "role_id": test_role_id.clone(),
        "secret_id": test_secret_id.clone(),
    });

    let first_response = ResponseTemplate::new(200).set_body_json(ApproleResponse {
        auth: ApproleAuthResponse {
            renewable: true,
            lease_duration: 0,
            token_policies: vec!["test".to_string()],
            accessor: "testAccessor".to_string(),
            client_token: "testToken".to_string(),
        },
        lease_duration: 0,
        renewable: false,
        lease_id: "".to_string(),
    });

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .and(body_json(&expected_body))
            .respond_with(first_response)
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

    println!("Before client");

    let config = hc_vault::Config {
        vault_url: mock_server.uri(),
        ..Default::default()
    };
    let tmp_client = match hc_vault::Client::new(config, tmp_auth) {
        Err(e) => {
            assert!(false, "Should not return error: {}", e);
            return;
        }
        Ok(s) => s,
    };

    println!("After client");

    task::block_on(mock_server.reset());

    let second_response = ResponseTemplate::new(200).set_body_json(ApproleResponse {
        auth: ApproleAuthResponse {
            renewable: true,
            lease_duration: 120,
            token_policies: vec!["test".to_string()],
            accessor: "testAccessor".to_string(),
            client_token: "concurrentToken".to_string(),
        },
        lease_duration: 0,
        renewable: false,
        lease_id: "".to_string(),
    });

    task::block_on(
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(second_response)
            .expect(1)
            .mount(&mock_server),
    );

    let client_arc = std::sync::Arc::new(tmp_client);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(5));
    let done_barrier = std::sync::Arc::new(std::sync::Barrier::new(6));

    for _ in 0..5 {
        let c = std::sync::Arc::clone(&barrier);
        let c_client = std::sync::Arc::clone(&client_arc);
        let c_done = std::sync::Arc::clone(&done_barrier);

        std::thread::spawn(move || {
            c.wait();
            match task::block_on(c_client.check_session()) {
                Err(e) => {
                    assert!(false, "Should not return error {}", e);
                }
                Ok(_) => {}
            };

            c_done.wait();
        });
    }

    done_barrier.wait();

    assert_eq!(client_arc.get_token(), String::from("concurrentToken"));
}
