pub mod error;
pub mod jwk;
pub mod jwt;

use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenidConfiguration {
    pub jwks_uri: String,
}
