use std::fmt;

/// The Error
#[derive(Debug)]
pub enum Error {
    /// ParseError is returned when there was an error parsing a url
    ParseError(url::ParseError),
    /// ReqwestError is returned when the request made to vault itself fails
    ReqwestError(reqwest::Error),
    /// IOError is returned by operations that have to do some sort of IO, like
    /// the helper function for the kubernetes backend, which loads the JWT token
    /// from a local file
    IOError(std::io::Error),
    /// InvalidRequest is returned when the made to vault was missing data or was invalid/
    /// malformed data and therefore was rejected by vault before doing anything
    InvalidRequest,
    /// IsSealed is returned when the given vault instance is not available because it
    /// is currently sealed and therefore does not accept or handle any requests other
    /// than to unseal it
    IsSealed,
    /// NotFound is returned when the given vault endpoint/path was not found on the
    /// actual vault instance that you are connected to
    NotFound,
    /// Unauthorized is returned when your current Session has either expired and has not
    /// been renewed or when the credentials for login are not valid and therefore rejected
    /// or when you try to access something that you dont have the permissions to do so
    Unauthorized,
    /// SessionExpired is returned when the session you tried to use is expired and was
    /// configured to not automatically obtain a new session, when it notices that the
    /// current one is expired
    SessionExpired,
    /// Other simply represents all other errors that could not be grouped into on the other
    /// categories listed above
    Other,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ParseError(ref cause) => write!(f, "Parse Error: {}", cause),
            Error::ReqwestError(ref cause) => write!(f, "Reqwest Error: {}", cause),
            Error::IOError(ref cause) => write!(f, "IO Error: {}", cause),
            Error::InvalidRequest => write!(f, "Invalid Request: Invalid or Missing data"),
            Error::IsSealed => write!(
                f,
                "The Vault instance is still sealed and can't be used at the moment"
            ),
            Error::NotFound => write!(f, "Not Found"),
            Error::Unauthorized => write!(f, "Unauthorized"),
            Error::SessionExpired => write!(f, "Session has expired, no auto login"),
            Error::Other => write!(f, "Unknown error"),
        }
    }
}

impl From<url::ParseError> for Error {
    fn from(cause: url::ParseError) -> Error {
        Error::ParseError(cause)
    }
}
impl From<reqwest::Error> for Error {
    fn from(cause: reqwest::Error) -> Error {
        Error::ReqwestError(cause)
    }
}
impl From<std::io::Error> for Error {
    fn from(cause: std::io::Error) -> Error {
        Error::IOError(cause)
    }
}

impl Error {
    /// Creates the corresponding Error based on the given Status-Code returned
    /// by the Vault-API
    pub fn from_status_code(code: u16) -> Self {
        match code {
            400 => Self::InvalidRequest,
            403 => Self::Unauthorized,
            404 => Self::NotFound,
            503 => Self::IsSealed,
            _ => Self::Other,
        }
    }
}

/// The possible errors returned by the Renew part of the Client
pub enum RenewError {
    /// Possible Errors returned by the Auth backend when you try to renew the
    /// current token/session
    AuthError(Error),
    /// This is returned if you try to run the Renew session part but without
    /// enabling the Renew Policy in the config
    NotEnabled,
    /// Returned when the current session can actually not be renewed
    NotRenewable,
}

impl fmt::Display for RenewError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RenewError::AuthError(ref cause) => {
                write!(f, "Error returned by Auth-Backend: {}", cause)
            }
            RenewError::NotEnabled => write!(f, "The Renew Policy is not enabled"),
            RenewError::NotRenewable => write!(f, "The current session can not be renewed"),
        }
    }
}

impl From<Error> for RenewError {
    fn from(cause: Error) -> RenewError {
        RenewError::AuthError(cause)
    }
}
