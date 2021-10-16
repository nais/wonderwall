# wonderwall

![anyway here's wonderwall](https://i.imgur.com/NhRLEej.png)

`wonderwall` is an application that implements _OpenID Connect_ (OIDC) in a way that makes it easy to plug into Kubernetes as a
sidecar. As such, this is OIDC as a sidecar, or OaaS, or to explain the joke: Oasis - Wonderwall

## Features

Wonderwall currently implements a client that
follows [ID-porten's preferred setup](https://docs.digdir.no/oidc_guide_idporten.html):

- OpenID Connect Authorization Code Flow with mandatory use of PKCE, state and nonce - aiming to be compliant with OAuth
  2.1.
- Validation of `id_token` in accordance with the OpenID Connect Core specifications.
- Client authentication with the authorization server as
  per [RFC 7523, Section 2.2](https://datatracker.ietf.org/doc/html/rfc7523).
- Support for [RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
- Support for [front-channel logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html).

Wonderwall functions as an optionally intercepting reverse proxy that proxies requests to a downstream host.

By default, it does not actually intercept any requests other than to remove the `Authorization` header if the user
agent does not have a valid session with Wonderwall.

## Endpoints

Wonderwall exposes and owns these endpoints (which means they will never be proxied downstream):

* `/oauth2/login` redirects the user to the Identity Provider to perform the OpenID Connect Authorization Code Flow.
* `/oauth2/callback` handles callbacks from Identity Provider as part of the OpenID Connect Authorization Code Flow.
* `/oauth2/logout` triggers self-initiated/RP-initiated logout.
* `/oauth2/logout/frontchannel` implements front-channel logout.

## Usage

In order to initiate authenticated user sessions, the user must be redirected to the `/oauth2/login` endpoint, which
performs the OIDC Auth Code flow. The user will then be redirected back to the downstream application, with
the `Authorization` header containing a `Bearer`
access token. As long as the user has an active session with Wonderwall, all further requests to the downstream
application will have the `Authorization` header set.

### Configuration

Wonderwall can be configured using either command-line flags or equivalent environment variables (i.e. `-`, `.` -> `_`
and uppercase), with `WONDERWALL_` as prefix. E.g.:

```text
openid.client-id -> WONDERWALL_OPENID_CLIENT_ID
```

The following flags are available:

```shell
Usage of ./bin/wonderwall
      --auto-login                               Automatically redirect user to login if the user does not have a valid session for all proxied downstream requests.
      --bind-address string                      Listen address for public connections. (default "127.0.0.1:8090")
      --encryption-key string                    Base64 encoded 256-bit cookie encryption key; must be identical in instances that share session store.
      --error-redirect-uri string                URI to redirect user to on errors for custom error handling.
      --ingress string                           Ingress used to access the main application. (default "/")
      --log-format string                        Log format, either 'json' or 'text'. (default "json")
      --log-level string                         Logging verbosity level. (default "debug")
      --metrics-bind-address string              Listen address for metrics only. (default "127.0.0.1:8091")
      --openid.acr-values.enabled                Toggle for setting the security level (acr_values) parameter for authorization requests.
      --openid.acr-values.value string           Space separated string that configures the requested acr_values.
      --openid.client-id string                  Client ID for the OpenID client.
      --openid.client-jwk string                 JWK containing the private key for the OpenID client in string format.
      --openid.post-logout-redirect-uri string   URI for redirecting the user after successful logout at the Identity Provider.
      --openid.provider string                   Provider configuration to load and use, either 'openid', 'azure', 'idporten'. (default "openid")
      --openid.redirect-uri string               Redirect URI for the OpenID client that should be used in authorization requests.
      --openid.scopes strings                    List of additional scopes (other than 'openid') that should be used during the login flow.
      --openid.ui-locales.enabled                Toggle for setting the UI locale parameter for authorization requests.
      --openid.ui-locales.value string           Space-separated string that configures the default locales for OAuth2 consent screen.
      --openid.well-known-url string             URI to the well-known OpenID Configuration metadata document.
      --redis.address string                     Address of Redis. An empty value will use in-memory session storage.
      --redis.password string                    Password for Redis.
      --redis.tls                                Whether or not to use TLS for connecting to Redis. (default true)
      --redis.username string                    Username for Redis.
      --session-max-lifetime duration            Max lifetime for user sessions. (default 1h0m0s)
      --upstream-host string                     Address of upstream host. (default "127.0.0.1:8080")
```

At minimum, the following configuration must be provided:

- `openid.client-id`
- `openid.client-jwk`
- `openid.redirect-uri`
- `openid.well-known-url`

#### ID-porten

When the `openid.provider` flag is set to `idporten`, the following environment variables are bound to the required
flags described previously:

- `IDPORTEN_CLIENT_ID`  
  Client ID for the client at ID-porten.
- `IDPORTEN_CLIENT_JWK`  
  Private key belonging to the client in JWK format.
- `IDPORTEN_REDIRECT_URI`  
  Valid pre-registered redirect URI that ID-porten should redirect the user to as part of the authentication flow.  
  For example: `http://localhost:8090/oauth2/callback`
- `IDPORTEN_WELL_KNOWN_URL`  
  Well-known OpenID Configuration endpoint for ID-porten: <https://docs.digdir.no/oidc_func_wellknown.html>.

The default values for the following flags are also changed:

| Flag | Value |
| ---- | ----- |
| `openid.acr-values.enabled` | `true` |
| `openid.acr-values.value` | `Level4` |
| `openid.ui-locales.enabled` | `true` |
| `openid.ui-locales.value` | `nb` |

#### Azure AD

When the `openid.provider` flag is set to `azure`, the following environment variables are bound to the required flags described previously:

- `AZURE_APP_CLIENT_ID`  
  Client ID for the client at Azure AD.
- `AZURE_APP_CLIENT_JWK`  
  Private key belonging to the client in JWK format.
- `AZURE_APP_REDIRECT_URI`  
  Valid pre-registered redirect URI that Azure AD should redirect the user to as part of the authentication flow.  
  For example: `http://localhost:8090/oauth2/callback`
- `AZURE_APP_WELL_KNOWN_URL`  
  Well-known OpenID Configuration endpoint for Azure AD.

## Development

### Requirements

- Go 1.17

### Setup

`make wonderwall` and `./bin/wonderwall`

See [configuration](#configuration). 

Optionally run the Redis server with `docker-compose up`.
