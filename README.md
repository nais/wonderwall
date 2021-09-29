# wonderwall

![anyway here's wonderwall](https://i.imgur.com/NhRLEej.png)

`wonderwall` is an application that implements OpenID Connect in a way that makes it easy to plug into Kubernetes as a sidecar.
As such, this is OIDC as a sidecar, or OaaS, or to explain the joke: Oasis - Wonderwall

## About

Wonderwall currently implements a client that follows [ID-porten's preferred setup](https://docs.digdir.no/oidc_guide_idporten.html):

- OpenID Connect Authorization Code Flow with mandatory use of PKCE, state and nonce - aiming to be compliant with OAuth 2.1.
- Validation of `id_token` in accordance with the OpenID Connect Core specifications.
- Client authentication with the authorization server as per [RFC 7523, Section 2.2](https://datatracker.ietf.org/doc/html/rfc7523).
- Support for [RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
- Support for [front-channel logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html).

### Endpoints

Wonderwall exposes and owns these endpoints (which means they will never be proxied downstream):

* `/oauth2/login` redirects the user to ID-porten to perform the OpenID Connect Authorization Code Flow.
* `/oauth2/callback` handles callbacks from ID-porten as part of the OpenID Connect Authorization Code Flow.
* `/oauth2/logout` triggers self-initiated/RP-initiated logout.
* `/oauth2/logout/frontchannel` implements front-channel logout.

### Functionality

Wonderwall functions as an optionally intercepting reverse proxy that proxies requests to a downstream host.

By default, it does not actually intercept any requests other than to remove the `Authorization` header if the user agent
does not have a valid session with Wonderwall.

### Usage

In order to initiate authenticated user sessions, the user must be redirected to the `/oauth2/login` endpoint, which performs
the OIDC Auth Code flow.
The user will then be redirected back to the downstream application, with the `Authorization` header containing a `Bearer`
access token. As long as the user has an active session with Wonderwall, all further requests to the downstream
application will have the `Authorization` header set.

## Development

### Requirements

- Go 1.17

### Configuration

#### Required

- `IDPORTEN_CLIENT_ID`  
  Client ID for the client at ID-porten.
- `IDPORTEN_CLIENT_JWK`  
  Private key belonging to the client in JWK format. 
- `IDPORTEN_REDIRECT_URI`  
  Valid pre-registered redirect URI that ID-porten should redirect the user to as part of the authentication flow.  
  For example: `http://localhost:8090/oauth2/callback`
- `IDPORTEN_WELL_KNOWN_URL`  
  Well-known OpenID Configuration endpoint for ID-porten: <https://docs.digdir.no/oidc_func_wellknown.html>.

#### Optional

Wonderwall can be configured using either command-line flags or equivalent environment variables (i.e. `-`, `.` -> `_` and uppercase).

Build with `make wonderwall` and run `./bin/wonderwall --help` to see the available flags.
