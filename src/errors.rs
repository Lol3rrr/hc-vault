use std::fmt;

/// The Error
#[derive(Debug)]
pub enum Error {
    /// ParseError is returned when there was an error parsing a url
    ParseError(url::ParseError),
    /// ReqwestError is returned when the request made to vault itself fails
    ReqwestError(reqwest::Error),
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
/// This is only meant for status codes and assumes that the
/// given u16 is a status-code from an http-request
impl From<u16> for Error {
    fn from(cause: u16) -> Error {
        match cause {
            400 => Error::InvalidRequest,
            403 => Error::Unauthorized,
            404 => Error::NotFound,
            503 => Error::IsSealed,
            _ => Error::Other,
        }
    }
}
