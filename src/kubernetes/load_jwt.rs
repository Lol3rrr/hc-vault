use crate::Error;

/// This function is a small helper function that reads the jwt
/// service account from the default mount location on disk in the pod.
pub fn load_jwt() -> Result<String, Error> {
    match std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token") {
        Err(e) => Err(Error::from(e)),
        Ok(s) => Ok(s),
    }
}
