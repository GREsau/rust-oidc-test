use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtParseError {
    MalformedHeader,
    MalformedPayload,
    MalformedSignature,
    WrongNumberOfParts(usize),
}

impl fmt::Display for JwtParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtParseError::MalformedHeader => write!(f, "JWT header is malformed."),
            JwtParseError::MalformedPayload => write!(f, "JWT payload is malformed."),
            JwtParseError::MalformedSignature => write!(f, "JWT signature is malformed."),
            JwtParseError::WrongNumberOfParts(num) => {
                write!(f, "Expected JWT to have 3 parts, but it has {}.", num)
            }
        }
    }
}

impl std::error::Error for JwtParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtVerifyError {
    InvalidSignature,
    UnsupportedAlgorithm(String),
    UnknownKid(String),
}

impl fmt::Display for JwtVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtVerifyError::InvalidSignature => write!(f, "JWT signature is not valid."),
            JwtVerifyError::UnsupportedAlgorithm(alg) => {
                write!(f, "JWT is using unsupported crypto algorithm: '{}'.", alg)
            }
            JwtVerifyError::UnknownKid(kid) => {
                write!(f, "JWT has 'kid' which was not found in JWKS: '{}'.", kid)
            }
        }
    }
}

impl std::error::Error for JwtVerifyError {}
