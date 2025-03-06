# Wonderwall

![anyway here's wonderwall](https://i.imgur.com/NhRLEej.png)

Wonderwall is a reverse proxy that implements an _OpenID Connect_ (OIDC) relying party (or client), primarily for use as a [Kubernetes _sidecar_](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/).

As such, this is OIDC as a sidecar, or OaaS, or to explain the joke:

> _Oasis - Wonderwall_

## Features

Wonderwall aims to be compliant with OAuth 2.1, and supports the following:

- [OpenID Connect Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) with mandatory use of [PKCE](https://datatracker.ietf.org/doc/html/rfc7636), state and nonce
- Client authentication using client assertions (`private_key_jwt`) ([RFC 7523, Section 2.2](https://datatracker.ietf.org/doc/html/rfc7523))
- [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Front-Channel Logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- [OAuth 2.0 Pushed Authorization Requests (RFC 9126)](https://datatracker.ietf.org/doc/html/rfc9126)
- Sessions stored in Redis, encrypted with XChaCha20-Poly1305.
- Two deployment modes:
  - Standalone mode (default) for zero-trust based setups where each application has its own perimeter and client
  - Single sign-on (SSO) mode for shared authentication across multiple applications on a common domain

Wonderwall fits in the backend-for-frontend (BFF) pattern as described in [Best Current Practices - OAuth 2.0 for Browser-Based Apps, section 6.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#name-backend-for-frontend-bff).

For further details, see [the documentation directory](docs):

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Endpoints](docs/endpoints.md)
- [Usage](docs/usage.md)
- [Sessions](docs/sessions.md)

## How it works

Wonderwall abstracts away the complexities of authentication and session management from your application,
making end-user authentication fairly straightforward.

### Unauthenticated requests

If the user does _not_ have a valid session, requests will be proxied to the upstream host as-is without modifications.

### Log in a user

To establish a session, redirect the user to the `/oauth2/login` endpoint.
This initiates the OpenID Connect Authorization Code Flow.

### Authenticated requests

If the user successfully completed the login flow, the sidecar creates and stores a session.
A corresponding session cookie is created and set before finally redirecting user agent to the application.

As long as the session is valid, the user's access token is attached for all requests to the upstream:

```http request
GET /some/path HTTP/1.1
Host: 127.0.0.1:8080
Authorization: Bearer <access_token>
```

### Log out a user

To log out, redirect the user to the `/oauth2/logout` endpoint.
This clears the session and redirects the user to the identity provider for single-logout.

## Quick start

See [docker-compose.example.yml](docker-compose.example.yml) for an example setup:

```shell
docker-compose -f docker-compose.example.yml up
```

### Unauthenticated request

Visit <http://localhost:3000>.

The response should be returned as-is from the upstream.
The `authorization` header should not be set.

### Log in

Visit <http://localhost:3000/oauth2/login>.

The `authorization` header should now be set in the upstream response.
The response should also include the decoded JWT from said header.

### Log out

Visit <http://localhost:3000/oauth2/logout>.

The `authorization` header should no longer be set in the upstream response.

## Development

Requires Go 1.24.

Start up dependencies:

```shell
docker-compose up -d
```

Start Wonderwall:

```shell
make local
```

## Docker Images

Wonderwall is available on both GitHub Container Registry and Google Artifact Registry:

- `ghcr.io/nais/wonderwall`
- `europe-north1-docker.pkg.dev/nais-io/nais/images/wonderwall`

For available tags, see [the versions overview on GitHub](https://github.com/nais/wonderwall/pkgs/container/wonderwall/versions).

### Verifying the Wonderwall image and its contents

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
