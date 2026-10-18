use aws_sdk_dynamodb::model::AttributeValue;
use axum::http::HeaderMap;
use axum::Json;

use crate::config;
use crate::errors::Error;
use crate::models::payment::MaskedCard;
use crate::pkg::db;
use crate::utils::authorization::authorize;

pub async fn method(headers: HeaderMap) -> Result<Json<Vec<MaskedCard>>, Error> {
    let user = authorize(headers).await?;

    let client = db::CLIENT.get().await;

    let query = client
        .query()
        .table_name(config::db::PAYMENTS_TABLE_NAME.clone())
        .key_condition_expression("#pk = :pk")
        .expression_attribute_names("#pk", "pk")
        .expression_attribute_values(":pk", AttributeValue::S(format!("uid#{}", user.email)))
        .send()
        .await;

    match query {
        Ok(result) => {
            if let Some(items) = result.items().map(|slice| slice.to_vec()) {
                let cards: Vec<MaskedCard> =
                    serde_dynamo::from_items(items).map_err(|_| {
                        log::error!("Failed to deserialize wallet items");
                        Error::internal_server_error()
                    })?;
                return Ok(Json(cards));
            }
            Ok(Json(vec![]))
        }
        Err(_) => {
            log::error!("DynamoDB query failed");
            Err(Error::bad_request())
        }
    }
}
