import boto3
import json
import base64
import argparse
import logging
import botocore.config


# Constants
CROSS_ACCOUNT_ROLE_ARN = "arn:aws:iam::111111111111:role/pki-serverlessca-x-account-role"
LAMBDA_FUNCTION_NAME = "serverless-tls-cert-dev"

# logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

def assume_role(role_arn):
    logger.info("Assuming cross-account role...")
    sts_client = boto3.client("sts")
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName="LambdaInvokeSession"
    )
    return response["Credentials"]

def read_and_encode_csr(csr_path):
    logger.info(f"Reading CSR file: {csr_path}")
    try:
        with open(csr_path, "rb") as csr_file:
            csr_content = csr_file.read()
        return base64.b64encode(csr_content).decode("utf-8")
    except Exception as e:
        logger.error(f"Failed to read CSR file: {e}")
        raise

def invoke_lambda(credentials, common_name, base64_csr_data, lifetime, force_issue):
    logger.info("Invoking Lambda function...")

    lambda_client = boto3.client(
        "lambda",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        verify=False
    )

    payload = {
        "common_name": common_name,
        "base64_csr_data": base64_csr_data,
        "lifetime": lifetime,
        "force_issue": force_issue 
    }

    try:
        response = lambda_client.invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload)
        )

        response_payload = json.loads(response["Payload"].read().decode("utf-8"))
        return response_payload
    except Exception as e:
        logger.error(f"Lambda invocation failed: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(description="Invoke AWS Lambda function for certificate signing.")
    parser.add_argument("--csr_path", help="Path to the CSR file")
    parser.add_argument("--common_name", help="Common Name (CN) for the certificate")
    parser.add_argument("--lifetime", default=30, help="The lifetime of the generated certificate. In days.")
    parser.add_argument("--force_issue", default=False, help="Force issue of certificate when private key has already been used")

    args = parser.parse_args()

    try:
        credentials = assume_role(CROSS_ACCOUNT_ROLE_ARN)
        base64_csr_data = read_and_encode_csr(args.csr_path)
        response = invoke_lambda(credentials, args.common_name, base64_csr_data, args.lifetime, args.force_issue)

        logger.info("Lambda function response:")
        print(json.dumps(response, indent=4))
    except Exception as e:
        logger.error(f"Script failed: {e}")

if __name__ == "__main__":
    main()

