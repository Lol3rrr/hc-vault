use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use url::Url;

use crate::Auth as AuthTrait;
use crate::Client;
use crate::Error;

/// The Config for Kubernetes Login
#[derive(Clone, Serialize)]
pub struct KubernetesLogin {
    /// The JWT Token to use for authentication
    pub jwt: String,
}

pub struct Session {
    kubernetes: KubernetesLogin,
}
