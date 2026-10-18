use std::collections::HashMap;

use crate::config;
use crate::models::common::EncryptedPayload;
use crate::models::payment::{MaskedCard, Payment};
use crate::pkg::{db, keyvault};
use crate::utils::authorization::authorize;
use crate::utils::payment::{categorize_card_number, get_last_4_digits};
use crate::{errors::Error, models::common::ResponseWrapper};
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_kms::model::EncryptionAlgorithmSpec;
use aws_sdk_kms::types::Blob;
use axum::http::HeaderMap;
use axum::{extract, Json};
use uuid::Uuid;
use validator::Validate;

pub async fn method(
    headers: HeaderMap,
    extract::Json(payload): extract::Json<EncryptedPayload>,
) -> Result<Json<ResponseWrapper>, Error> {
    let user = authorize(headers).await?;

    let client = keyvault::CLIENT.get().await;

    let cipher = base64::decode(&payload.encrypted_payload).map_err(|_| Error::bad_request())?;

    let result = client
        .decrypt()
        .key_id(config::keyvault::RSA_KEY_ID.clone())
        .encryption_algorithm(EncryptionAlgorithmSpec::RsaesOaepSha256)
        .ciphertext_blob(Blob::new(cipher))
        .send()
        .await;

    match result {
        Ok(result) => {
            let plaintext = result
                .plaintext()
                .ok_or_else(Error::internal_server_error)?;

            let decrypted = String::from_utf8(plaintext.as_ref().to_vec())
                .map_err(|_| Error::bad_request())?;
            let payment: Payment =
                serde_json::from_str(&decrypted).map_err(|_| Error::bad_request())?;

            payment.validate().map_err(|_| Error::bad_request())?;

            let card_id = Uuid::new_v4();
            let last_digits =
                get_last_4_digits(&payment.card.number).ok_or_else(Error::bad_request)?;
            let masked = MaskedCard {
                id: card_id.to_string(),
                name: payment.name,
                expiration: payment.card.expiration,
                last_digits,
                network: categorize_card_number(&payment.card.number),
            };

            let pk: AttributeValue = AttributeValue::S(format!("uid#{}", user.email));
            let sk: AttributeValue = AttributeValue::S(format!("card#{}", card_id));

            let mut item: HashMap<String, AttributeValue> = serde_dynamo::to_item(masked)
                .map_err(|_| {
                    log::error!("Failed to serialize masked card");
                    Error::internal_server_error()
                })?;
            item.insert(String::from("pk"), pk);
            item.insert(String::from("sk"), sk);

            item.insert(
                String::from("encrypted"),
                AttributeValue::S(payload.encrypted_payload),
            );

            let client = db::CLIENT.get().await;
            match client
                .put_item()
                .table_name(config::db::PAYMENTS_TABLE_NAME.clone())
                .set_item(Some(item))
                .send()
                .await
            {
                Ok(_) => (),
                Err(_) => {
                    log::error!("DynamoDB PutItem failed");
                    return Err(Error::internal_server_error());
                }
            };

            Ok(Json(ResponseWrapper {
                message: String::from("success"),
            }))
        }

        Err(_) => {
            log::error!("KMS decrypt failed");
            Err(Error::internal_server_error())
        }
    }
}
