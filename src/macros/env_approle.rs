/// This macro automatically creates an approle Auth-Session from certain
/// Environment variables
///
/// NOTE: This macro DOES panic if it can't find an ID or Secret and also panics
/// if the actually creation of the Session fails.
///
/// Environment-Variables:
/// * `APPROLE_ID`: The ID of the Approle-Role to use
/// * `APPROLE_SECRET`: The Secret of the Approle-Role to use
#[macro_export]
macro_rules! env_approle {
    () => {{
        let id = std::env::var("APPROLE_ID").unwrap();
        let secret = std::env::var("APPROLE_SECRET").unwrap();

        approle::Session::new(id, secret).unwrap()
    }};
}
