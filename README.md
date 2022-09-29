# wonderwall

![anyway here's wonderwall](https://i.imgur.com/NhRLEej.png)

`wonderwall` is an application that implements an _OpenID Connect_ (OIDC) relying party/client in a way that makes it 
easy to plug into Kubernetes as a sidecar. As such, this is OIDC as a sidecar, or OaaS, or to explain the joke: 
Oasis - Wonderwall

## Features

Wonderwall aims to be compliant with OAuth 2.1, and supports the following:

- OpenID Connect Authorization Code Flow with mandatory use of PKCE, state and nonce
- Client authentication using client assertions (`private_key_jwt`) as
  per [RFC 7523, Section 2.2](https://datatracker.ietf.org/doc/html/rfc7523).
- [RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
- [Front-channel logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html).

Wonderwall functions as an optionally intercepting reverse proxy that proxies requests to a downstream host.

By default, it does not actually intercept any requests other than to remove the `Authorization` header if the user
agent does not have a valid session with Wonderwall.

## Overview

The image below shows the overall architecture of an application when using Wonderwall as a sidecar:

![Wonderwall architecture](docs/assets/wonderwall-architecture.png)

The sequence diagram below shows the default behavior of Wonderwall:

![Wonderwall sequence diagram](docs/assets/wonderwall-sequence.png)

Generally speaking, the recommended approach when using the Wonderwall sidecar is to put it in front of
your backend-for-frontend server that serves your frontend. Otherwise, you might run into issues with the cookie
configuration and allowed redirects - these are both effectively restricted to only match the domain and path for your
application's ingress.

## Endpoints

Wonderwall exposes and owns these endpoints (which means they will never be proxied downstream).

Endpoints that are available for use by applications:

| Path                      | Description                                                                                    |
|---------------------------|------------------------------------------------------------------------------------------------|
| `/oauth2/login`           | Initiates the OpenID Connect Authorization Code flow                                           |
| `/oauth2/logout`          | Initiates local and global/single-logout                                                       |
| `/oauth2/session`         | Returns the current user's session metadata                                                    |
| `/oauth2/session/refresh` | Refreshes the tokens for the user's session. Requires the `session.refresh` flag to be enabled |

Endpoints that should be registered at and only be triggered by identity providers:

| Path                          | Description                                                                                |
|-------------------------------|--------------------------------------------------------------------------------------------|
| `/oauth2/callback`            | Handles the callback from the identity provider                                            |
| `/oauth2/logout/callback`     | Handles the logout callback from the identity provider                                     |
| `/oauth2/logout/frontchannel` | Handles global logout request (initiated by identity provider on behalf of another client) |

## Usage

If the user does _not_ have a valid local session with the sidecar, the request will be proxied as-is without
modifications to the upstream host.

In order to obtain a local session, the user must be redirected to the `/oauth2/login` endpoint, which performs the
OpenID Connect Authorization Code Flow.

If the user successfully completed the login flow, the sidecar creates and stores a session. A corresponding session 
cookie is created and set before finally redirecting user agent to the application. All requests that 
are forwarded to the application container will now contain an `Authorization` header with the user's `access_token`
as a Bearer token.

Do note that cookies are set for the most specific subdomain and path (if any) defined in the `ingress` configuration
variable.

### Configuration

Wonderwall can be configured using either command-line flags or equivalent environment variables (i.e. `-`, `.` -> `_`
and uppercase), with `WONDERWALL_` as prefix. E.g.:

```text
openid.client-id -> WONDERWALL_OPENID_CLIENT_ID
```

The following flags are available:

```shell
--auto-login                               Automatically redirect all HTTP GET requests to login if the user does not have a valid session for all matching upstream paths.
--auto-login-ignore-paths strings          Comma separated list of absolute paths to ignore when 'auto-login' is enabled. Supports basic wildcard matching with glob-style single asterisks using the stdlib path.Match. Invalid patterns are ignored.
--bind-address string                      Listen address for public connections. (default "127.0.0.1:3000")
--encryption-key string                    Base64 encoded 256-bit cookie encryption key; must be identical in instances that share session store.
--error-path string                        Absolute path to redirect user to on errors for custom error handling.
--ingress strings                          Comma separated list of ingresses used to access the main application.
--log-format string                        Log format, either 'json' or 'text'. (default "json")
--log-level string                         Logging verbosity level. (default "info")
--loginstatus.cookie-domain string         The domain that the cookie should be set for.
--loginstatus.cookie-name string           The name of the cookie.
--loginstatus.enabled                      Feature toggle for Loginstatus, a separate service that should provide an opaque token to indicate that a user has been authenticated previously, e.g. by another application in another subdomain.
--loginstatus.resource-indicator string    The resource indicator that should be included in the authorization request to get an audience-restricted token that Loginstatus accepts. Empty means no resource indicator.
--loginstatus.token-url string             The URL to the Loginstatus service that returns an opaque token.
--metrics-bind-address string              Listen address for metrics only. (default "127.0.0.1:3001")
--openid.acr-values string                 Space separated string that configures the default security level (acr_values) parameter for authorization requests.
--openid.client-id string                  Client ID for the OpenID client.
--openid.client-jwk string                 JWK containing the private key for the OpenID client in string format.
--openid.post-logout-redirect-uri string   URI for redirecting the user after successful logout at the Identity Provider.
--openid.provider string                   Provider configuration to load and use, either 'openid', 'azure', 'idporten'. (default "openid")
--openid.scopes strings                    List of additional scopes (other than 'openid') that should be used during the login flow.
--openid.ui-locales string                 Space-separated string that configures the default UI locale (ui_locales) parameter for OAuth2 consent screen.
--openid.well-known-url string             URI to the well-known OpenID Configuration metadata document.
--redis.address string                     Address of Redis. An empty value will use in-memory session storage.
--redis.password string                    Password for Redis.
--redis.tls                                Whether or not to use TLS for connecting to Redis. (default true)
--redis.username string                    Username for Redis.
--session.inactivity                       Automatically expire user sessions if they have not refreshed their tokens within a given duration.
--session.inactivity-timeout duration      Inactivity timeout for user sessions. (default 30m0s)
--session.max-lifetime duration            Max lifetime for user sessions. (default 1h0m0s)
--session.refresh                          Automatically refresh the tokens for user sessions if they are expired, as long as the session exists (indicated by the session max lifetime).
--upstream-host string                     Address of upstream host. (default "127.0.0.1:8080")
```

Boolean flags/options are by default set to `false` unless noted otherwise.

At minimum, the following configuration must be provided:

- `openid.client-id`
- `openid.client-jwk`
- `openid.well-known-url`
- `ingress`

#### ID-porten

When the `openid.provider` flag is set to `idporten`, the following environment variables are bound to the required `openid`
flags described previously:

- `IDPORTEN_CLIENT_ID`  
  Client ID for the client at ID-porten.
- `IDPORTEN_CLIENT_JWK`  
  Private key belonging to the client in JWK format.
- `IDPORTEN_WELL_KNOWN_URL`  
  Well-known OpenID Configuration endpoint for ID-porten: <https://docs.digdir.no/oidc_func_wellknown.html>.

The default values for the following flags are also changed:

| Flag                | Value    |
|---------------------|----------|
| `openid.acr-values` | `Level4` |
| `openid.ui-locales` | `nb`     |

#### Azure AD

When the `openid.provider` flag is set to `azure`, the following environment variables are bound to the required flags
described previously:

- `AZURE_APP_CLIENT_ID`  
  Client ID for the client at Azure AD.
- `AZURE_APP_CLIENT_JWK`  
  Private key belonging to the client in JWK format.
- `AZURE_APP_WELL_KNOWN_URL`  
  Well-known OpenID Configuration endpoint for Azure AD.

## Session Management

Sessions are stored server-side; we only store a session identifier at the end-user's user agent. 
For production use, we strongly recommend setting up and connecting to Redis.

Sessions can be configured with a maximum lifetime with the `session.max-lifetime` flag, which accepts Go duration strings
(e.g. `10h`, `5m`, `30s`, etc.).

There's also an endpoint that returns metadata about the user's session as a JSON object at `GET /oauth2/session`. This
endpoint will respond with HTTP status codes on errors:

- `401 Unauthorized` - no session cookie or matching session found (e.g. user is not authenticated, or has logged out)
- `500 Internal Server Error` - the session store is unavailable, or Wonderwall wasn't able to process the request

Otherwise, an `HTTP 200 OK` is returned with the metadata with the `application/json` as the `Content-Type`.

#### Example

Request:

```
GET /oauth2/session
```

Response:

```
HTTP/2 200 OK
Content-Type: application/json
```

```json
{
  "session": {
    "created_at": "2022-08-31T06:58:38.724717899Z", 
    "ends_at": "2022-08-31T16:58:38.724717899Z",
    "timeout_at": "0001-01-01T00:00:00Z",
    "ends_in_seconds": 14658,
    "active": true,
    "timeout_in_seconds": -1
  },
  "tokens": {
    "expire_at": "2022-08-31T14:03:47.318251953Z",
    "refreshed_at": "2022-08-31T12:53:58.318251953Z",
    "expire_in_seconds": 4166
  }
}
```

Most of these fields should be self-explanatory, but we'll be explicit with their description:

| Field                        | Description                                                                                                          |
|------------------------------|----------------------------------------------------------------------------------------------------------------------|
| `session.created_at`         | The timestamp that denotes when the session was first created.                                                       |
| `session.ends_at`            | The timestamp that denotes when the session will end.                                                                |
| `session.timeout_at`         | The timestamp that denotes when the session will time out. The zero-value, `0001-01-01T00:00:00Z`, means no timeout. |
| `session.ends_in_seconds`    | The number of seconds until the session ends.                                                                        |
| `session.active`             | Whether or not the session is marked as active.                                                                      |
| `session.timeout_in_seconds` | The number of seconds until the session times out. A value of `-1` means no timeout.                                 |
| `tokens.expire_at`           | The timestamp that denotes when the tokens within the session will expire.                                           |
| `tokens.refreshed_at`        | The timestamp that denotes when the tokens within the session was last refreshed.                                    |
| `tokens.expire_in_seconds`   | The number of seconds until the tokens expire.                                                                       |

### Refresh Tokens

Tokens within the session will usually expire before the session itself. If you've configured a longer session lifetime,
you'll probably want to use refresh tokens to avoid redirecting end-users to the `/oauth2/login` endpoint whenever the
access tokens have expired. This can be enabled by using the `session.refresh` flag.

If session refresh is enabled, tokens will at the earliest be automatically renewed 5 minutes before they expire. This
happens whenever the end-user visits any path that is proxied to the upstream application.

The `session.refresh` flag also enables a new endpoint:

- `POST /oauth2/session/refresh` - manually refreshes the tokens for the user's session, and returns the metadata like in 
`/oauth2/session` described previously

#### Example

Request:

```
POST /oauth2/session/refresh
```

Response:

```
HTTP/2 200 OK
Content-Type: application/json
```

```json
{
  "session": {
    "created_at": "2022-08-31T06:58:38.724717899Z", 
    "ends_at": "2022-08-31T16:58:38.724717899Z",
    "ends_in_seconds": 14658
  },
  "tokens": {
    "expire_at": "2022-08-31T14:03:47.318251953Z",
    "refreshed_at": "2022-08-31T12:53:58.318251953Z",
    "expire_in_seconds": 4166,
    "next_auto_refresh_in_seconds": 3866,
    "refresh_cooldown": true,
    "refresh_cooldown_seconds": 37
  }
}
```

Additionally, the metadata object returned by both the `/oauth2/session` and `/oauth2/session/refresh` endpoints now 
contain some new fields in addition to the previous fields:

| Field                                 | Description                                                                                     |
|---------------------------------------|-------------------------------------------------------------------------------------------------|
| `tokens.next_auto_refresh_in_seconds` | The number of seconds until the earliest time where the tokens will automatically be refreshed. |
| `tokens.refresh_cooldown`             | A boolean indicating whether or not the refresh operation is on cooldown or not.                |
| `tokens.refresh_cooldown_seconds`     | The number of seconds until the refresh operation is no longer on cooldown.                     |

Note that the refresh operation has a default cooldown period of 1 minute, which may be shorter depending on the token lifetime
of the tokens returned by the identity provider. In other words, a request to the `/oauth2/session/refresh` endpoint will 
only trigger a refresh if `tokens.refresh_cooldown` is `false`.

### Inactivity

A session can be marked as inactive if the time since last refresh exceeds a given timeout. This is useful if you want
to ensure that an end-user can re-authenticate with the identity provider if they've been gone from an authenticated
session for some time. 

This is enabled with the `session.inactivity` option, which also requires `session.refresh`.

The `/oauth2/session` endpoint returns `session.active`, `session.timeout_at` and `session.timeout_in_seconds` that
indicates the state of the session and when it times out.

The timeout is configured with `session.inactivity-timeout`. If this timeout is shorter than the token lifetime, you 
should implement mechanisms to trigger refreshes before the timeout is reached.

## Development

### Requirements

- Go 1.19

### Binary

`make wonderwall` and `./bin/wonderwall`

See [configuration](#configuration).

### Docker Compose

See the [docker-compose file](docker-compose.yml) for an example setup:

- Requires an environment variable `WONDERWALL_OPENID_CLIENT_JWK` with a private JWK. 
  - This can be acquired from <https://mkjwk.org>.
  - Set the environment variable in an `.env` file that Docker Compose automatically detects and uses
  - Environment variables can be finicky with escaping, so try to wrap the value with single quotation marks.
    - E.g. `WONDERWALL_OPENID_CLIENT_JWK='{ "p": "_xCP...", ... }'`.
- You need to be able to reach `host.docker.internal` to reach the identity provider mock, so make sure you 
have `127.0.0.1 host.docker.internal` in your `/etc/hosts` file.
- By default, the setup will use the latest available pre-built image.
  - If you want to will build a fresh binary from the cloned source, replace the following

```yaml
services:
  ...
  wonderwall:
    image: ghcr.io/nais/wonderwall:latest
 ```

with 

```yaml
services:
  ...
  wonderwall:
    build: .
```

Run `docker-compose up`. This starts:

- Wonderwall
- Redis as the session storage
- [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) as an identity provider
- [http-https-echo](https://hub.docker.com/r/mendhak/http-https-echo) as a dummy upstream server

Try it out:

1. Visit <http://localhost:3000>
   1. The response should be returned as-is from the upstream.
   2. The `authorization` header should not be set.
2. Visit <http://localhost:3000/oauth2/login>
   1. The `authorization` header should now be set in the upstream response.
   2. The response should also include the decoded JWT from said header.
3. Visit <http://localhost:3000/oauth2/logout>
   1. The `authorization` header should no longer be set in the upstream response.
