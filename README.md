# Sanitarium

Sanitarium is a tool for running an SSH client certificate authority, using OpenID Connect for authentication.

> **WARNING**: This code is still relatively new, has not had a security audit. The API may change as a result of future changes.

For Linux systems with a TPM2 device onboard, it is able to protect intermediate credentials with the TPM.


## Building

There are both a server and client part in the same repository.
To build them, you will need to have the Go compiler, Git and [trousers](http://trousers.sourceforge.net/) instealled.

To install these requirements on a Fedora or RHEL system, run: `dnf install -y golang git trousers-devel`

To build the server, we will need to get the list of trusted TPM vendor certificates extracted.
This is not part of the repository, so that it gets rebuilt upon user request.
To do that, you will need to install `cabextract` (`dnf install -y cabextract`) and then run `go generate ./...`.

After this, you can change to either the `server/` or `client/` directory, and run `go build`.

For the client, it might be useful to compile in the URL-base of the server you are intending to use, which you can accomplish with:
`go build -ldflags "-X github.com/puiterwijk/sanitarium/client/internal/config.DefaultServerRoot=https://somewhere"`


## Deploying the server

First, generate the intermediate and SSH certificate signing keys:

```
openssl genrsa -out intermediate.key 2048
ssh-keygen -t rsa -b 2048 -f sshkey -m PKCS8
```

You can toss out the generated `sshkey.pub`. The public key will be extracted by the server upon start.

The configuration of the server happens via environment variables.

Booleans can be specified as "yes", "true" or "1" for true, or "off", "false" or "0" for false.
Validity periods can be specified in a number and a possible suffix according to the [documentation](https://golang.org/pkg/time/#ParseDuration).

| Environment variable   | Meaning |
|------------------------|---------|
| `SERVICE_ROOT`         | The URL the server will be made available on, without trailing slash. |
| `OIDC_PROVIDER_ROOT`   | The base of the OpenID Connect provider URL. |
| `OIDC_CLIENT_ID`       | The client ID to use for authenticating to the OpenID Connect provider. |
| `OIDC_CLIENT_SECRET`   | The client secret for the OpenID Connect provider. |
| `OIDC_SUPPORTS_OOB`    | A boolean whether or not the OpenID Connect provider supports the `urn:ietf:wg:oauth:2.0:oob` URL for out of band token returning. |
| `OIDC_REQUIRED_SCOPES` | A comma separated list of scopes to request from the OpenID Connect provider. Needs to ensure the provider returns the claim used (defaults to `openid`). |
| `OIDC_TOKEN_INFO_URL`  | The URL to the OpenID Connect TokenInfo endpoint for verifying whether all required scopes were approved by the user. Scopes will not be checked if empty. |
| `OIDC_USERNAME_CLAIM`  | The claim to use as the username in the SSH certificates. |
| `INTERMEDIATE_CERT_VALIDITY` | The validity period of intermediate certificates (defaults to `8h`). |
| `INTERMEDIATE_SIGNING_KEY_PATH` | The path to the intermediate certificate signing key. |
| `SSH_CERT_VALIDITY`    | The validity period of issued SSH certificates (defaults to `5m`). |
| `SSH_CERT_SIGNING_KEY` | The path to the SSH certificate signing key. |
| `REQUIRE_TPM`          | A boolean whether a TPM from a well-known TPM vendor is required. This will also be used to protect the intermediate certificates. |
| `REQUIRE_MEASUREMENT`  | A boolean whether TPM-attested measurements are required. The event log will be checked against the PCRs attested and. **WARNING** verification of event log entries is not yet implemented! |
