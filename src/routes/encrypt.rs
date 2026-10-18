use aws_sdk_kms::{model::EncryptionAlgorithmSpec, types::Blob};
use axum::http::HeaderMap;
use axum::{extract, Json};
use serde_json::Value;

use crate::utils::authorization::authorize;
use crate::{config, errors::Error, models::common::EncryptedPayload, pkg::keyvault};

pub async fn post_encrypt(
    headers: HeaderMap,
    extract::Json(payment): extract::Json<Value>,
) -> Result<Json<EncryptedPayload>, Error> {
    let _user = authorize(headers).await?;

    let client = keyvault::CLIENT.get().await;

    let json_string =
        serde_json::to_string(&payment).map_err(|_| Error::bad_request())?;

    match client
        .encrypt()
        .key_id(config::keyvault::RSA_KEY_ID.clone())
        .encryption_algorithm(EncryptionAlgorithmSpec::RsaesOaepSha256)
        .plaintext(Blob::new(json_string.as_bytes().to_vec()))
        .send()
        .await
    {
        Ok(result) => {
            let blob = result
                .ciphertext_blob()
                .ok_or_else(Error::internal_server_error)?;
            let bytes = blob.as_ref();

            Ok(Json(EncryptedPayload {
                encrypted_payload: base64::encode(bytes),
            }))
        }
        Err(_) => {
            log::error!("KMS encrypt failed");
            Err(Error::internal_server_error())
        }
    }
}
