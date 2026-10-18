import { Construct } from "constructs";
import * as cdk from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as path from "path";
import * as apigwv2 from "@aws-cdk/aws-apigatewayv2-alpha";
import * as kms from "aws-cdk-lib/aws-kms";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as integration from "@aws-cdk/aws-apigatewayv2-integrations-alpha";

export class ApiStack extends cdk.Stack {
  public readonly key: kms.IKey;
  public readonly table: dynamodb.ITable;
  public readonly fn: lambda.IFunction;
  public readonly api: apigwv2.HttpApi;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    this.table = new dynamodb.Table(this, "rust_payment_table", {
      tableName: "wallet",
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    });

    this.key = new kms.Key(this, "rust_payment_key", {
      alias: "rust_payment_key",
      keySpec: kms.KeySpec.RSA_4096,
      keyUsage: kms.KeyUsage.ENCRYPT_DECRYPT,
    });

    // provided.al2023 has GLIBC >= 2.34; cargo-lambda/zig builds need 2.28+.
    // CDK 2.68 has no PROVIDED_AL2023 constant, so construct the runtime explicitly.
    const runtime = new lambda.Runtime(
      "provided.al2023",
      lambda.RuntimeFamily.OTHER
    );

    this.fn = new lambda.Function(this, "rust_payment_api_lambda", {
      functionName: "rust_payment_api_lambda",
      runtime,
      architecture: lambda.Architecture.ARM_64,
      handler: "bootstrap",
      code: new lambda.AssetCode(
        path.join(__dirname, "../../target/lambda/rust-api/bootstrap.zip")
      ),
      environment: {
        DYNAMODB_ENDPOINT: "https://dynamodb.us-east-1.amazonaws.com",
        PAYMENTS_TABLE_NAME: this.table.tableName,
        KMS_ENDPOINT: "https://kms.us-east-1.amazonaws.com",
        KMS_RSA_KEY_ID: this.key.keyId,
        GOOGLE_OAUTH_CLIENT_ID:
          "104079326466-rqglh7msot9iphnvv3qeodqs4j29i8ld.apps.googleusercontent.com",
      },
    });

    this.table.grantReadWriteData(this.fn);
    this.key.grantEncryptDecrypt(this.fn);
    this.key.grant(this.fn, "kms:GetPublicKey");

    // Handle OPTIONS at the API Gateway so preflight never depends on Lambda health.
    this.api = new apigwv2.HttpApi(this, "rust_payment_http_api", {
      corsPreflight: {
        allowHeaders: ["authorization", "content-type"],
        allowMethods: [
          apigwv2.CorsHttpMethod.GET,
          apigwv2.CorsHttpMethod.POST,
          apigwv2.CorsHttpMethod.OPTIONS,
        ],
        allowOrigins: [
          "http://localhost:5173",
          "https://wallet.amuel.org",
        ],
        allowCredentials: true,
        maxAge: cdk.Duration.days(1),
      },
    });

    this.api.addRoutes({
      path: "/",
      methods: [apigwv2.HttpMethod.ANY],
      integration: new integration.HttpLambdaIntegration(
        "http-lambda-integration",
        this.fn
      ),
    });

    this.api.addRoutes({
      path: "/{proxy+}",
      methods: [apigwv2.HttpMethod.ANY],
      integration: new integration.HttpLambdaIntegration(
        "http-lambda-integration",
        this.fn
      ),
    });
  }
}
