use crate::error::{Category, VerificationError};
use crate::jwt::{Jwt, UnverifiedJwt};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub fn get_key<'a>(&'a self, kid: &str) -> Option<&'a Jwk> {
        self.keys
            .iter()
            .find(|k| k.kid.as_ref().map(String::as_ref) == Some(kid))
    }

    pub fn verify<'a>(&self, jwt: UnverifiedJwt<'a>) -> Result<Jwt, VerificationError<'a>> {
        let kid = &jwt.header().kid;
        match self.get_key(kid) {
            Some(jwk) => jwk.verify(jwt),
            None => Err(VerificationError::new(Category::UnknownKid, jwt)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
}

impl Jwk {
    pub fn modulus(&self) -> Option<Vec<u8>> {
        b64_decode(self.n.as_ref()?).ok()
    }

    pub fn exponent(&self) -> Option<Vec<u8>> {
        b64_decode(self.e.as_ref()?).ok()
    }

    pub fn verify<'a>(&self, jwt: UnverifiedJwt<'a>) -> Result<Jwt, VerificationError<'a>> {
        match (self.modulus(), self.exponent()) {
            (Some(n), Some(e)) => jwt.verify(&n, &e),
            _ => Err(VerificationError::new(Category::JwkMissingRsaParams, jwt)),
        }
    }
}

fn b64_decode(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let config = base64::URL_SAFE_NO_PAD.decode_allow_trailing_bits(true);
    base64::decode_config(encoded, config)
}
