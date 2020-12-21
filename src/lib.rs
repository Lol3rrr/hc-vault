#![warn(missing_docs)]
//! Async, highly concurrent crate to interact with vault and its mounts

/// The Approle Auth-Backend in vault
pub mod approle;
/// The Database module is used for all interactions with the database backend in vault
pub mod database;
/// The Kubernetes Auth-Backend in vault
pub mod kubernetes;
/// The kv2 module is used for all interactions with the v2 key-value backend in vault
pub mod kv2;
/// The token module is used for all basic interactions with a simple client-token and no other
/// backend
pub mod token;

mod client;
mod errors;
mod internals;

pub use client::*;
pub use errors::*;

/// This trait needs to be implemented by all auth backends to be used for
/// authenticating using that backend
pub trait Auth {
    /// Checking if the current session is expired and needs to be renewed or dropped
    ///
    /// Safety:
    /// This function is expected to be called from mulitple Threads at the same time
    /// in an unsychronized way, even while the Auth-Backend is in the middle of an
    /// Auth-Operation
    fn is_expired(&self) -> bool;
    /// Used to actually authenticate with the backend and obain a new valid session
    /// that can be used for further requests to vault
    ///
    /// Safety:
    /// This function is always called in a synchronized manner during which
    /// no other Thread is readinh the Token. This allows for optimizations and
    /// techniques to be used that rely on exclusive access to the Token when it
    /// is being updated, but not while reading it. This helps to avoid any
    /// Mutexes/Locks in the Auth-Backend.
    fn auth(&self, vault_url: &str) -> Result<(), Error>;
    /// Returns the vault token that can be used to make requests to vault
    /// as the current session
    ///
    /// Safety:
    /// This function is expected to be called from mulitple Threads at the same
    /// time in an unsychronized way, but not while the Backend is doing a single
    /// Auth-Operation
    fn get_token(&self) -> String;
    /// Returns if the current token can be renewed using this auth-backend.
    /// This is used to decide whether or not to try to renew the session before
    /// it is expired or letting the session expire and then simply obtaining a
    /// new one the next time it is used.
    ///
    /// Safety:
    /// This function is only called by a single, maybe two, threads.
    fn is_renewable(&self) -> bool;
    /// Returns the total duration for which the current token is valid for
    /// in seconds
    ///
    /// Safety:
    /// This function is only expected to be called by the background thread that
    /// is responsible for renewing a token
    fn get_total_duration(&self) -> u64;
    /// This is used to actually renew the Tokens lease
    ///
    /// Safety:
    /// This function is only expected to be called by the background thread that
    /// renews the token
    fn renew(&self) -> Result<(), Error>;
}

/// The RenewPolicy describes how the vault client should deal with expired
/// vault session
pub enum RenewPolicy {
    /// Reauth causes the vault client to acquire a completly new vault session, via the
    /// provided auth config, if the old one expired. This is a lazy operation,
    /// so it only checks if it needs a new session before making a request
    Reauth,
    /// Renew causes the vault client to try and renew a token as long and as often as
    /// possible without ever letting it actually expire.
    /// The float should be a value between 0-1 and represents the percentage (0=0%, 1=100%)
    /// of time that should be remaining before a session/token is renewed.
    ///
    /// Example:
    /// With a threshold of 0.25 and a total Token Duration of 60m, the Token will be renewed
    /// after 45m/ when only 15min are left.
    Renew(f32),
    /// Nothing does nothing when the session expires. This will cause the client to always
    /// return a SessionExpired error when trying to request anything from vault
    Nothing,
}

/// The Configuration for the vault client
pub struct Config {
    /// The URL the client should use to connect to the vault instance
    pub vault_url: String,
    /// The Policy the client should use to handle sessions expiring
    ///
    /// Default: RenewPolicy::Reauth
    pub renew_policy: RenewPolicy,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            vault_url: "http://localhost:8200".to_string(),
            renew_policy: RenewPolicy::Reauth,
        }
    }
}
