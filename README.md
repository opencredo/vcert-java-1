# VCert-Java

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>  

VCert is a Java library, SDK, designed to simplify key generation and enrollment of machine identities
(also known as SSL/TLS certificates and keys) that comply with enterprise security policy by using the
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://pki.venafi.com/venafi-cloud/).

## Acceptance Tests

To run the acceptance tests the following environment variables must be set:

| NAME | NOTES |
|------|-------|
| VENAFI_USER | |
| VENAFI_PASSWORD | |
| VENAFI_TPP_URL | Only for TPP connector tests |
| VENAFI_API_KEY | Taken from account after logged in |
| VENAFI_CERT_COMMON_NAME | Used for cert creation, should match configured domains |
| VENAFI_CLOUD_URL | Only for cloud connector tests |
| VENAFI_ZONE | Only for cloud connector tests |
