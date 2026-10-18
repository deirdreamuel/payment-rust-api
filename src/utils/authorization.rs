use crate::{errors::Error, models::user::User};
use axum::http::HeaderMap;
use base64::{decode_config, URL_SAFE_NO_PAD};
use lazy_static::lazy_static;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use reqwest;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::env::var;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const AUTHORIZATION_HEADER_KEY: &str = "Authorization";
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
const JWKS_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

lazy_static! {
    static ref JWKS_CACHE: RwLock<Option<JwksCache>> = RwLock::new(None);
}

struct JwksCache {
    fetched_at: Instant,
    /// kid -> PEM-encoded public key
    keys: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct GoogleIdTokenClaims {
    iss: String,
    aud: String,
    #[serde(default)]
    azp: Option<String>,
    email: String,
    #[serde(deserialize_with = "deserialize_email_verified")]
    email_verified: bool,
    #[serde(default)]
    name: Option<String>,
    exp: u64,
}

fn deserialize_email_verified<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    match Value::deserialize(deserializer)? {
        Value::Bool(v) => Ok(v),
        Value::String(s) => Ok(s.eq_ignore_ascii_case("true")),
        other => Err(D::Error::custom(format!(
            "unexpected email_verified value: {:?}",
            other
        ))),
    }
}

pub async fn authorize(headers: HeaderMap) -> Result<User, Error> {
    let token = get_token_from_headers(&headers)?;
    verify_auth_token(&token).await
}

fn get_token_from_headers(headers: &HeaderMap) -> Result<String, Error> {
    let auth_header = headers
        .get(AUTHORIZATION_HEADER_KEY)
        .ok_or_else(Error::unauthorized)?;

    let token_string = auth_header.to_str().map_err(|_| Error::unauthorized())?;

    let token = token_string
        .strip_prefix("Bearer ")
        .ok_or_else(Error::unauthorized)?
        .trim();

    if token.is_empty() {
        return Err(Error::unauthorized());
    }

    Ok(token.to_string())
}

pub async fn verify_auth_token(id_token: &str) -> Result<User, Error> {
    let client_id = var("GOOGLE_OAUTH_CLIENT_ID").unwrap_or_default();
    if client_id.is_empty() {
        log::error!("GOOGLE_OAUTH_CLIENT_ID is not configured");
        return Err(Error::unauthorized());
    }

    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::unauthorized());
    }

    let header_json = decode_b64_url(parts[0])?;
    let payload_json = decode_b64_url(parts[1])?;
    let signature = decode_b64_url_bytes(parts[2])?;

    let header: Value =
        serde_json::from_slice(&header_json).map_err(|_| Error::unauthorized())?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "RS256" {
        return Err(Error::unauthorized());
    }
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(Error::unauthorized)?;

    let pem = get_public_key_pem(kid).await?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    if !verify_rs256(&pem, signing_input.as_bytes(), &signature)? {
        log::error!("Google ID token signature verification failed");
        return Err(Error::unauthorized());
    }

    let claims: GoogleIdTokenClaims =
        serde_json::from_slice(&payload_json).map_err(|_| Error::unauthorized())?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::unauthorized())?
        .as_secs();
    if claims.exp <= now {
        log::error!("Google ID token is expired");
        return Err(Error::unauthorized());
    }

    if claims.iss != GOOGLE_ISSUERS[0] && claims.iss != GOOGLE_ISSUERS[1] {
        log::error!("Google ID token has unexpected issuer");
        return Err(Error::unauthorized());
    }

    if claims.aud != client_id {
        log::error!("Google ID token has unexpected audience");
        return Err(Error::unauthorized());
    }

    if let Some(azp) = claims.azp.as_deref() {
        if azp != client_id {
            log::error!("Google ID token has unexpected azp");
            return Err(Error::unauthorized());
        }
    }

    if !claims.email_verified {
        log::error!("Rejected Google ID token with unverified email");
        return Err(Error::unauthorized());
    }

    Ok(User {
        email: claims.email,
        name: claims.name.unwrap_or_default(),
    })
}

async fn get_public_key_pem(kid: &str) -> Result<String, Error> {
    if let Some(pem) = cached_pem(kid) {
        return Ok(pem);
    }

    refresh_jwks().await?;

    cached_pem(kid).ok_or_else(|| {
        log::error!("Google JWKS did not contain kid for token");
        Error::unauthorized()
    })
}

fn cached_pem(kid: &str) -> Option<String> {
    let cache = JWKS_CACHE.read().ok()?;
    let entry = cache.as_ref()?;
    if entry.fetched_at.elapsed() > JWKS_CACHE_TTL {
        return None;
    }
    entry.keys.get(kid).cloned()
}

async fn refresh_jwks() -> Result<(), Error> {
    let response = reqwest::Client::new()
        .get(GOOGLE_JWKS_URL)
        .send()
        .await
        .map_err(|_| {
            log::error!("Failed to fetch Google JWKS");
            Error::unauthorized()
        })?;

    if !response.status().is_success() {
        log::error!("Google JWKS request returned non-success status");
        return Err(Error::unauthorized());
    }

    let jwks = response.json::<JwksResponse>().await.map_err(|_| {
        log::error!("Failed to parse Google JWKS response");
        Error::unauthorized()
    })?;

    let mut keys = HashMap::new();
    for jwk in jwks.keys {
        match jwk_to_pem(&jwk.n, &jwk.e) {
            Ok(pem) => {
                keys.insert(jwk.kid, pem);
            }
            Err(_) => {
                log::error!("Skipping invalid Google JWK entry");
            }
        }
    }

    if keys.is_empty() {
        log::error!("Google JWKS contained no usable keys");
        return Err(Error::unauthorized());
    }

    let mut cache = JWKS_CACHE
        .write()
        .map_err(|_| Error::internal_server_error())?;
    *cache = Some(JwksCache {
        fetched_at: Instant::now(),
        keys,
    });

    Ok(())
}

fn jwk_to_pem(n_b64: &str, e_b64: &str) -> Result<String, Error> {
    let n_bytes = decode_b64_url_bytes(n_b64)?;
    let e_bytes = decode_b64_url_bytes(e_b64)?;

    let n = BigNum::from_slice(&n_bytes).map_err(|_| Error::unauthorized())?;
    let e = BigNum::from_slice(&e_bytes).map_err(|_| Error::unauthorized())?;
    let rsa = Rsa::from_public_components(n, e).map_err(|_| Error::unauthorized())?;
    let pem = rsa
        .public_key_to_pem()
        .map_err(|_| Error::unauthorized())?;
    String::from_utf8(pem).map_err(|_| Error::unauthorized())
}

fn verify_rs256(pem: &str, signing_input: &[u8], signature: &[u8]) -> Result<bool, Error> {
    let rsa = Rsa::public_key_from_pem(pem.as_bytes()).map_err(|_| Error::unauthorized())?;
    let pkey = PKey::from_rsa(rsa).map_err(|_| Error::unauthorized())?;
    let mut verifier =
        Verifier::new(MessageDigest::sha256(), &pkey).map_err(|_| Error::unauthorized())?;
    verifier
        .update(signing_input)
        .map_err(|_| Error::unauthorized())?;
    verifier
        .verify(signature)
        .map_err(|_| Error::unauthorized())
}

fn decode_b64_url(input: &str) -> Result<Vec<u8>, Error> {
    decode_b64_url_bytes(input)
}

fn decode_b64_url_bytes(input: &str) -> Result<Vec<u8>, Error> {
    decode_config(input, URL_SAFE_NO_PAD).map_err(|_| Error::unauthorized())
}
