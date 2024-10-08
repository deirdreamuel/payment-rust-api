# Rust Axum Api using Lambda with Api Gateway Proxy Integration
The following is a Rust Axum Api using Lambda with Api Gateway Proxy integration. This application uses DynamoDB for storage.

## System Diagram
![payment_rust_api_architecture](https://github.com/user-attachments/assets/86115eee-7db4-4774-bf2f-1d384bccd2ff)

### Prerequisites
1. `Rust` (https://www.rust-lang.org/learn/get-started).
2. `Cargo Lambda` (https://www.cargo-lambda.info/guide/getting-started.html).

### Required Environment Variables
- PAYMENTS_TABLE_NAME
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_DEFAULT_REGION
- DYNAMODB_ENDPOINT
- KMS_ENDPOINT
- KMS_RSA_KEY_ID

### Running Locally
1. Run `cargo lambda watch -a 127.0.0.1 -p 8080` or `make run`.

### Deploying Project
1. Run `cargo lambda build --release --arm64  --output-format zip`.
2. Deploy AWS Lambda function with Api Gateway `/` and `{proxy+}` resources with `ANY` method. With `bootstrap` as handler and `arm64` architecture.
3. Upload zip file located in `/target/lambda/<PROJECT_NAME>/bootstrap.zip` after build.

