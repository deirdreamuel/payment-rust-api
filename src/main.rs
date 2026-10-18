use axum::{
    http::{header, HeaderValue, Method},
    routing::{get, post},
    Router,
};
use lambda_http::Error;
use tower_http::cors::CorsLayer;

mod config;
mod errors;
mod models;
mod pkg;
mod routes;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();

    env_logger::init();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_ansi(false)
        .without_time()
        .init();

    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:5173".parse::<HeaderValue>().unwrap(),
            "https://wallet.amuel.org".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_credentials(true);

    let app = Router::new()
        .route(
            "/default/wallet",
            get(routes::payments::get_payments::method)
                .post(routes::payments::create_payment::method),
        )
        .route("/default/publickey", get(routes::publickey::get_publickey))
        .route("/default/encrypt", post(routes::encrypt::post_encrypt))
        .layer(cors);

    lambda_http::run(app).await
}
