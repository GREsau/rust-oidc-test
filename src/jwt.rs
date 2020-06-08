use crate::error::{JwtParseError, JwtVerifyError};
use crate::jwk::Jwk;
use core::fmt;
use ring::signature::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwt {
    encoded: String,
    payload_end: usize,
    header: JwtHeader,
    payload: JwtPayload,
    signature: Vec<u8>,
}

impl Jwt {
    pub fn new(encoded: String) -> Result<Self, JwtParseError> {
        if encoded.is_empty() {
            return Err(JwtParseError::WrongNumberOfParts(0));
        }

        let mut parts = encoded.split('.');
        let header_part = parts.next().ok_or(JwtParseError::WrongNumberOfParts(0))?;
        let payload_part = parts.next().ok_or(JwtParseError::WrongNumberOfParts(1))?;
        let signature_part = parts.next().ok_or(JwtParseError::WrongNumberOfParts(2))?;
        let payload_end = header_part.len() + 1 + payload_part.len();

        match parts.count() {
            0 => {}
            n => return Err(JwtParseError::WrongNumberOfParts(n + 3)),
        }

        let header = Self::decode_header(header_part).ok_or(JwtParseError::MalformedHeader)?;
        let payload = Self::decode_payload(payload_part).ok_or(JwtParseError::MalformedPayload)?;
        let signature =
            Self::decode_signature(signature_part).ok_or(JwtParseError::MalformedSignature)?;
        Ok(Self {
            encoded,
            payload_end,
            header,
            payload,
            signature,
        })
    }

    fn decode_header(header_part: &str) -> Option<JwtHeader> {
        let json_bytes = b64_decode(header_part).ok()?;
        let json = std::str::from_utf8(&json_bytes).ok()?;
        serde_json::from_str(json).ok()
    }

    fn decode_payload(payload_part: &str) -> Option<JwtPayload> {
        let json_bytes = b64_decode(payload_part).ok()?;
        let json = std::str::from_utf8(&json_bytes).ok()?;
        serde_json::from_str(json).ok()
    }

    fn decode_signature(signature_part: &str) -> Option<Vec<u8>> {
        b64_decode(signature_part).ok()
    }

    pub fn header(&self) -> &JwtHeader {
        &self.header
    }

    pub fn payload(&self) -> &JwtPayload {
        &self.payload
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    pub fn verify(&self, jwk: &Jwk) -> Result<(), JwtVerifyError> {
        let alg = self.header.alg.as_str();

        if let Some(jwk_alg) = &jwk.alg {
            if alg != jwk_alg {
                return Err(JwtVerifyError::InvalidSignature);
            }
        }

        match alg {
            "RS256" => self.verify_rsa(jwk, &RSA_PKCS1_2048_8192_SHA256),
            "RS384" => self.verify_rsa(jwk, &RSA_PKCS1_2048_8192_SHA384),
            "RS512" => self.verify_rsa(jwk, &RSA_PKCS1_2048_8192_SHA512),
            "PS256" => self.verify_rsa(jwk, &RSA_PSS_2048_8192_SHA256),
            "PS384" => self.verify_rsa(jwk, &RSA_PSS_2048_8192_SHA384),
            "PS512" => self.verify_rsa(jwk, &RSA_PSS_2048_8192_SHA512),
            "ES256" => self.verify_ecdsa(jwk, &ECDSA_P256_SHA256_FIXED),
            "ES384" => self.verify_ecdsa(jwk, &ECDSA_P384_SHA384_FIXED),
            // "ES512" => requires https://github.com/briansmith/ring/issues/824
            _ => Err(JwtVerifyError::UnsupportedAlgorithm(alg.to_string())),
        }
    }

    fn verify_rsa(&self, jwk: &Jwk, alg: &RsaParameters) -> Result<(), JwtVerifyError> {
        if jwk.kty != "RSA" {
            return Err(JwtVerifyError::InvalidSignature);
        }

        let message = &self.encoded[..self.payload_end];
        let components = match jwk.rsa_components() {
            Some(c) => c,
            None => return Err(JwtVerifyError::InvalidSignature),
        };

        components
            .verify(alg, message.as_bytes(), &self.signature)
            .map_err(|_| JwtVerifyError::InvalidSignature)
    }

    fn verify_ecdsa(
        &self,
        jwk: &Jwk,
        alg: &EcdsaVerificationAlgorithm,
    ) -> Result<(), JwtVerifyError> {
        if jwk.kty != "EC" {
            return Err(JwtVerifyError::InvalidSignature);
        }

        let message = &self.encoded[..self.payload_end];
        let public_key = match jwk.ecdsa_public_key() {
            Some(c) => c,
            None => return Err(JwtVerifyError::InvalidSignature),
        };

        alg.verify(
            public_key.as_slice().into(),
            message.as_bytes().into(),
            self.signature.as_slice().into(),
        )
        .map_err(|_| JwtVerifyError::InvalidSignature)
    }
}

impl fmt::Display for Jwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

impl FromStr for Jwt {
    type Err = JwtParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
    pub kid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct JwtPayload(Value);

impl<'de> Deserialize<'de> for JwtPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map = <Map<String, Value>>::deserialize(deserializer)?;
        Ok(Self(Value::Object(map)))
    }
}

impl JwtPayload {
    pub fn claims(&self) -> &Map<String, Value> {
        self.0.as_object().unwrap()
    }

    pub fn get_claim<'a>(&'a self, name: &str) -> Option<&'a Value> {
        self.0.get(name)
    }

    pub fn has_claim(&self, name: &str, value: impl PartialEq<Value>) -> bool {
        let claim = match self.get_claim(name) {
            Some(claim) => claim,
            None => return false,
        };
        match claim.as_array() {
            Some(array) => array.iter().any(|v| value == *v),
            None => value == *claim,
        }
    }

    pub fn deserialize_as<T: serde::de::DeserializeOwned>(&self) -> serde_json::Result<T> {
        T::deserialize(&self.0)
    }
}

fn b64_decode(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let config = base64::URL_SAFE_NO_PAD.decode_allow_trailing_bits(true);
    base64::decode_config(encoded, config)
}
