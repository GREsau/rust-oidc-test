use crate::jwt::UnverifiedJwt;
use core::fmt;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct VerificationError<'a> {
    category: Category,
    jwt: UnverifiedJwt<'a>,
}

impl<'a> VerificationError<'a> {
    pub fn new(category: Category, jwt: UnverifiedJwt<'a>) -> Self {
        VerificationError {
            category,
            jwt,
        }
    }

    pub fn into_unverified_jwt(self) -> UnverifiedJwt<'a> {
        self.jwt
    }

    pub fn classify(&self) -> Category {
        self.category
    }
}

impl fmt::Display for VerificationError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.classify() {
            Category::JwkMissingRsaParams => {
                write!(f, "JWK is missing required RSA parameters ('n' and 'e').")
            }
            Category::InvalidSignature => write!(f, "JWT signature is not valid."),
            Category::UnsupportedAlgorithm => write!(
                f,
                "JWT is using unsupported crypto algorithm: '{}'.",
                &self.jwt.header().alg
            ),
            Category::UnknownKid  => write!(
                f,
                "JWT has 'kid' which was not found in JWKS: '{}'.",
                &self.jwt.header().kid
            ),
        }
    }
}

impl std::error::Error for VerificationError<'_> {}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Category {
    JwkMissingRsaParams,
    InvalidSignature,
    UnsupportedAlgorithm,
    UnknownKid,
}
