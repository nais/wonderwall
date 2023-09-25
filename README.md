# wonderwall

![anyway here's wonderwall](https://i.imgur.com/NhRLEej.png)

Wonderwall is an application that implements an _OpenID Connect_ (OIDC) relying party/client in a way that makes it 
easy to plug into Kubernetes applications as a _sidecar_.

As such, this is OIDC as a sidecar, or OaaS, or to explain the joke: 

> _Oasis - Wonderwall_

Wonderwall functions as a reverse proxy that should be placed in front of your application; intercepting and proxying requests.
It provides endpoints to perform logins and logouts for end users, along with session management - so that your application does not have to.

## Features

Wonderwall aims to be compliant with OAuth 2.1, and supports the following:

- OpenID Connect Authorization Code Flow with mandatory use of PKCE, state and nonce
- Client authentication using client assertions (`private_key_jwt`) as
  per [RFC 7523, Section 2.2](https://datatracker.ietf.org/doc/html/rfc7523)
- OpenID Connect [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- OpenID Connect [Front-Channel Logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- Encrypted sessions with XChaCha20-Poly1305, stored using Redis as the backend
- Two deployment modes:
  - Standalone mode (default) for zero-trust based setups where each application has its own perimeter and client
  - Single sign-on (SSO) mode for shared authentication across multiple applications on a common domain

## Documentation

At a glance, end-user authentication using Wonderwall is fairly straightforward:

- If the user does _not_ have a valid local session with the sidecar, requests will be proxied to the upstream host as-is without modifications.
- In order to obtain a local session, the user must be redirected to the `/oauth2/login` endpoint, which will initiate the
  OpenID Connect Authorization Code Flow.
    - If the user successfully completed the login flow, the sidecar creates and stores a session. A corresponding session cookie is created and set before finally redirecting user agent to the application.
    - All requests that are forwarded to the upstream host will now contain an `Authorization` header with the user's `access_token` as a Bearer token, as long as the session is not expired or inactive.
- In order to log out, the user must be redirected to the `/oauth2/logout` endpoint.

Detailed documentation can be found in the [documentation](docs) directory:

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Endpoints](docs/endpoints.md)
- [Usage](docs/usage.md)
  - [Session Management](docs/sessions.md)

## Running Locally

Requires Go 1.21

`make run`

## Docker Compose

See the [docker-compose file](docker-compose.yml) for an example setup:

- You need to be able to reach `host.docker.internal` to reach the identity provider mock, so make sure you
  have `127.0.0.1 host.docker.internal` in your `/etc/hosts` file.
- By default, the setup will use the latest available pre-built image.

Run `docker-compose up`. This starts:

- Wonderwall (port 3000) with Redis as the session storage
- [http-https-echo](https://hub.docker.com/r/mendhak/http-https-echo) (port 4000) as the upstream server
- [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) as the identity provider

Try it out:

1. Visit <http://localhost:3000>
    1. The response should be returned as-is from the upstream.
    2. The `authorization` header should not be set.
2. Visit <http://localhost:3000/oauth2/login>
    1. The `authorization` header should now be set in the upstream response.
    2. The response should also include the decoded JWT from said header.
3. Visit <http://localhost:3000/oauth2/logout>
    1. The `authorization` header should no longer be set in the upstream response.

## Verifying the Wonderwall image and its contents

The image is signed "keylessly" using [Sigstore cosign](https://github.com/sigstore/cosign).
To verify its authenticity run
```
cosign verify europe-north1-docker.pkg.dev/nais-io/nais/images/wonderwall@sha25:<shasum> \
--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
--certificate-identity "https://github.com/nais/wonderwall/.github/workflows/deploy.yml@refs/heads/master"
```

The images are also attested with SBOMs in the [CycloneDX](https://cyclonedx.org/) format.
You can verify these by running
```
cosign verify-attestation --type cyclonedx \
--certificate-identity "https://github.com/nais/wonderwall/.github/workflows/deploy.yml@refs/heads/master" \
--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
europe-north1-docker.pkg.dev/nais-io/nais/images/wonderwall@sha25:<shasum>
```
