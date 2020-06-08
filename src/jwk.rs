use crate::error::JwtVerifyError;
use crate::jwt::Jwt;
use ring::signature::RsaPublicKeyComponents;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub fn get_key<'a>(&'a self, kid: &str) -> Option<&'a Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }

    pub fn verify(&self, jwt: &Jwt) -> Result<(), JwtVerifyError> {
        let kid = jwt
            .header()
            .kid
            .as_deref()
            .ok_or(JwtVerifyError::UnknownKid(String::new()))?;
        match self.get_key(kid) {
            Some(jwk) => jwk.verify(jwt),
            None => Err(JwtVerifyError::UnknownKid(kid.to_string())),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

impl Jwk {
    pub fn modulus(&self) -> Option<Vec<u8>> {
        b64_decode(self.n.as_ref()?).ok()
    }

    pub fn exponent(&self) -> Option<Vec<u8>> {
        b64_decode(self.e.as_ref()?).ok()
    }

    pub fn x(&self) -> Option<Vec<u8>> {
        b64_decode(self.x.as_ref()?).ok()
    }

    pub fn y(&self) -> Option<Vec<u8>> {
        b64_decode(self.y.as_ref()?).ok()
    }

    pub fn verify(&self, jwt: &Jwt) -> Result<(), JwtVerifyError> {
        jwt.verify(self)
    }

    pub(crate) fn rsa_components(&self) -> Option<RsaPublicKeyComponents<Vec<u8>>> {
        match (self.modulus(), self.exponent()) {
            (Some(n), Some(e)) => Some(RsaPublicKeyComponents { n, e }),
            _ => None,
        }
    }

    pub(crate) fn ecdsa_public_key(&self) -> Option<Vec<u8>> {
        match (self.x(), self.y()) {
            (Some(x), Some(y)) => {
                let mut result = Vec::with_capacity(1 + x.len() + y.len());

                // first octet 0x04 indicates no point compression
                result.push(4);
                result.extend(x);
                result.extend(y);
                Some(result)
            }
            _ => None,
        }
    }
}

fn b64_decode(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let config = base64::URL_SAFE_NO_PAD.decode_allow_trailing_bits(true);
    base64::decode_config(encoded, config)
}
