"""Authentication failures should lead back to native inputs, not software installs."""
import pytest


def test_aws_missing_credentials_uses_native_form_guidance():
    from botocore.exceptions import NoCredentialsError
    from discovr.aws import AWSDiscovery
    class Missing:
        region_name = "us-east-1"
        def client(self, *args, **kwargs):
            return self
        def get_caller_identity(self):
            raise NoCredentialsError()
    with pytest.raises(RuntimeError, match="access key and secret in the AWS form"):
        AWSDiscovery(session=Missing()).run()


def test_azure_failed_auth_uses_native_form_guidance():
    from azure.core.exceptions import ClientAuthenticationError
    from discovr.azure import AzureDiscovery
    class Missing:
        def get_token(self, *args):
            raise ClientAuthenticationError("test credentials unavailable")
    with pytest.raises(RuntimeError, match="Client secret in the Azure form"):
        AzureDiscovery(credential=Missing())._token()


def test_gcp_missing_credentials_uses_native_form_guidance(monkeypatch):
    from google.auth.exceptions import DefaultCredentialsError
    from discovr.gcp import GCPDiscovery
    def missing(**kwargs):
        raise DefaultCredentialsError("test credentials unavailable")
    monkeypatch.setattr("google.auth.default", missing)
    with pytest.raises(RuntimeError, match="JSON key in the Google Cloud form"):
        GCPDiscovery()._session()
