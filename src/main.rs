use rust_oidc_test::{jwk::Jwks, jwt::Jwt, OpenIdConfiguration};
use serde::Deserialize;
use std::error::Error;
use std::io::stdin;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Enter JWT...");

    let mut jwt_string = String::new();
    stdin().read_line(&mut jwt_string)?;

    let jwt = Jwt::new(jwt_string.trim())?;

    let iss = jwt
        .payload()
        .get_claim("iss")
        .expect("Missing issuer claim")
        .as_str()
        .expect("Issuer claim not string");

    println!("Found issuer: {}", iss);

    let config_uri = format!("{}/.well-known/openid-configuration", iss);
    println!("Requesting config from {}", config_uri);
    let jwks_uri = reqwest::get(&config_uri)
        .await?
        .json::<OpenIdConfiguration>()
        .await?
        .jwks_uri;

    println!("Requesting jwks from {}", jwks_uri);
    let jwks: Jwks = reqwest::get(&jwks_uri).await?.json::<Jwks>().await?;

    jwks.verify(&jwt).map_err(|e| e.to_string())?;

    println!("{}", serde_json::to_string_pretty(&jwt.payload())?);

    let user = jwt.payload().deserialize_as::<User>()?;
    println!("{:?}", user);

    Ok(())
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct User<'a> {
    sub: &'a str,
    name: &'a str,
    scope: Vec<&'a str>,
}
