use std::time::{Duration, Instant};

use crate::Auth as AuthTrait;
use crate::Error;

/// The actual token-auth session that can be used to
/// authenticate with vault
pub struct Session {
    token: String,
    token_start: Instant,
    token_duration: Duration,
}

impl AuthTrait for Session {
    fn is_expired(&self) -> bool {
        self.token_start.elapsed() >= self.token_duration
    }
    fn get_token(&self) -> String {
        self.token.clone()
    }
    fn auth(&self, _vault_url: &str) -> Result<(), Error> {
        Ok(())
    }
    fn is_renewable(&self) -> bool {
        true
    }
    fn get_total_duration(&self) -> u64 {
        0
    }
    fn renew(&self, _vault_url: &str) -> Result<(), Error> {
        Ok(())
    }
}

impl Session {
    /// Used to obtain a new valid auth session that can
    /// be used with the vault client to authenticate
    pub fn new(token: String, token_duration: Duration) -> Result<Session, Error> {
        Ok(Session {
            token,
            token_start: Instant::now(),
            token_duration,
        })
    }
}
