use crate::error::{Category, JwtParseError, VerificationError};
use core::fmt;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct UnverifiedJwt<'a> {
    encoded: &'a str,
    payload_end: usize,
    header: JwtHeader,
    payload: JwtPayload,
    signature: Vec<u8>,
}

impl<'a> UnverifiedJwt<'a> {
    pub fn new(encoded: &'a str) -> Result<Self, JwtParseError> {
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
        Ok(UnverifiedJwt {
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

    pub fn unverified_payload(&self) -> &JwtPayload {
        &self.payload
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn verify(self, modulus: &[u8], exponent: &[u8]) -> Result<Jwt, VerificationError<'a>> {
        let alg = match self.header.alg.as_ref() {
            "RS256" => &RSA_PKCS1_2048_8192_SHA256,
            _ => return Err(VerificationError::new(Category::UnsupportedAlgorithm, self)),
        };

        let message = &self.encoded[..self.payload_end];
        let components = RsaPublicKeyComponents {
            n: modulus,
            e: exponent,
        };
        if components
            .verify(alg, message.as_bytes(), &self.signature)
            .is_err()
        {
            return Err(VerificationError::new(Category::InvalidSignature, self));
        }

        Ok(Jwt {
            header: self.header,
            payload: self.payload,
        })
    }
}

impl fmt::Display for UnverifiedJwt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

#[derive(Debug, Clone)]
pub struct Jwt {
    pub header: JwtHeader,
    pub payload: JwtPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    pub typ: String,
    pub alg: String,
    pub kid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JwtPayload(Map<String, Value>);

impl JwtPayload {
    pub fn claims(&self) -> &Map<String, Value> {
        &self.0
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

    pub fn deserialize_into<T: serde::de::DeserializeOwned>(self) -> serde_json::Result<T> {
        serde_json::from_value(Value::Object(self.0))
    }
}

fn b64_decode(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let config = base64::URL_SAFE_NO_PAD.decode_allow_trailing_bits(true);
    base64::decode_config(encoded, config)
}
