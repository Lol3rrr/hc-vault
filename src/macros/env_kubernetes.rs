/// This macro automatically creates a kubernetes Auth-Session from certain
/// Environment variables
///
/// NOTE: This macro DOES panic if it can't find a Role or the JWT file and
/// can also panic when creating the actual Session fails
///
/// Environment-Variables:
/// * `VAULT_ROLE`: The Role for the Kubernetes Auth method
/// Environment-Files:
/// * `/var/run/secrets/kubernetes.io/serviceaccount/token`:
/// The JWT token for the Service-Account associated with the Auth-Role
#[macro_export]
macro_rules! env_kubernetes {
    () => {{
        let role = std::env::var("VAULT_ROLE").unwrap();
        let jwt = kubernetes::load_jwt().unwrap();

        kubernetes::Session::new(role, jwt).unwrap()
    }};
}
