# Endpoints

Wonderwall exposes and owns these endpoints (which means they will never be proxied to the upstream application).

## Endpoints for applications

Endpoints that are available for use by applications:

| Path                           | Description                                                          | Notes                                             |
|--------------------------------|----------------------------------------------------------------------|---------------------------------------------------|
| `GET /oauth2/login`            | Initiates the OpenID Connect Authorization Code flow                 |                                                   |
| `GET /oauth2/logout`           | Performs local logout and redirects the user to global/single-logout |                                                   |
| `GET /oauth2/logout/local`     | Performs local logout only                                           | Disabled when `openid.provider` is `idporten`.    |
| `GET /oauth2/session`          | Returns the current user's session metadata                          |                                                   |
| `POST /oauth2/session/refresh` | Refreshes the tokens for the user's session.                         | Requires the `session.refresh` flag to be enabled |

## Endpoints for Identity Providers

Endpoints that should be registered at and only be triggered by identity providers:

| Path                              | Description                                                                                |
|-----------------------------------|--------------------------------------------------------------------------------------------|
| `GET /oauth2/callback`            | Handles the callback from the identity provider                                            |
| `GET /oauth2/logout/callback`     | Handles the logout callback from the identity provider                                     |
| `GET /oauth2/logout/frontchannel` | Handles global logout request (initiated by identity provider on behalf of another client) |

## Endpoint Details

The `/oauth2/login` and `/oauth2/logout` endpoints respond with HTTP 3xx status codes, as these OpenID Connect flows inherently rely on browser redirects.
As such, the use of these endpoints require that user agents are _redirected_. Using the Fetch API or XHR with these endpoints will fail.

The `/oauth2/login` and `/oauth2/logout` endpoints also accept query parameters at runtime that can override configured defaults.
These can be used to control redirect URLs and some OpenID Connect request parameters, if supported by the identity
provider. As always, query parameter string values should be URL-encoded.

---

### `/oauth2/login`

Redirect the user here to initiate the OpenID Connect Authorization Code flow.

| Query Parameter | Description                                                                                                                                               | Notes                                                                                                                                                                             |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `redirect`      | Where the user will be redirected after successful callback from the Identity Provider. Must be a relative URL with an absolute path, or an absolute URL. | For standalone or SSO proxy mode, this effectively only allows relative URLs. For SSO server mode, the domain must match any subdomain and path within the configured SSO domain. |
| `level`         | The `acr_values` parameter for the OpenID Connect authentication request.                                                                                 | Value must be declared as supported by the Identity Provider through the `acr_values_supported` property in the metadata document.                                                |
| `locale`        | The `ui_locales` parameter for the OpenID Connect authentication request                                                                                  | Value must be declared as supported by the Identity Provider through the `ui_locales_supported` property in the metadata document.                                                |

The user will be sent to the identity provider for authentication, and then back to the `/oauth2/callback` endpoint.

Following this, the user will be redirected using the following priority:

1. To the URL provided in the `redirect` query parameter in the initial login-request.
2. If the query parameter was not set or invalid, the redirect will point to different places depending on the [runtime mode](configuration.md#modes):
   - Standalone: the context root for the matching ingress that received the HTTP request.
   - SSO: the default URL configured using the `sso.server-default-redirect-url` flag.

---

### `/oauth2/logout`

Redirect the user here to clear the session along with local cookies, and to initiate the OpenID Connect RP-Initiated Logout flow.

| Query Parameter | Description                                                                                                                                               | Notes                                                                                                                                                                             |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `redirect`      | Where the user will be redirected after successful callback from the Identity Provider. Must be a relative URL with an absolute path, or an absolute URL. | For standalone or SSO proxy mode, this effectively only allows relative URLs. For SSO server mode, the domain must match any subdomain and path within the configured SSO domain. |

The user will be sent to the identity provider for logout, and then back to the `/oauth2/logout/callback` endpoint.

Following this, the user will be redirected using the following priority:

1. To the URL provided in the `redirect` query parameter in the initial logout-request.
2. If the query parameter was not set or invalid, the URL in the `openid.post-logout-redirect-uri` will be used.
3. If the `openid.post-logout-redirect-uri` flag is not set or empty, to the context root for the matching ingress that received the HTTP request.

---

### `/oauth2/logout/local`

Perform a `GET` request from the user agent (e.g. using the Fetch API or XHR) to this endpoint to clear the session along with local cookies.

**This does _not_ perform single sign-out at the identity provider; use the `/oauth2/logout` endpoint instead if you intend to log a user out globally.**

This endpoint only responds with a HTTP 204 No Content on successful local logout.

It may respond with a HTTP 500 if the session could not be cleared.

---

### `/oauth2/session`

Perform a `GET` request from the user agent to receive metadata about the user's session as a JSON object.

This endpoint will respond with the following HTTP status codes on errors:

- `HTTP 401 Unauthorized` - no session cookie or matching session found, or maximum lifetime reached
- `HTTP 500 Internal Server Error` - the session store is unavailable, or Wonderwall wasn't able to process the request

Otherwise, an `HTTP 200 OK` is returned with the metadata with the `application/json` as the `Content-Type`.

Note that this endpoint will still return `HTTP 200 OK` for [_inactive_ sessions](sessions.md#session-inactivity), as long as the session is not [_expired_](sessions.md#session-expiry).
This allows applications to display errors before redirecting the user to login on timeouts.
This also means that you should not use the HTTP response status codes alone as an indication of whether the user is authenticated or not.

#### Request:

```
GET /oauth2/session
```

#### Response:

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

| Field                                 | Description                                                                                                                                                   |
|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `session.active`                      | Whether or not the session is marked as active. If `false`, the session cannot be extended and the user must be redirected to login.                          |
| `session.created_at`                  | The timestamp that denotes when the session was first created.                                                                                                |
| `session.ends_at`                     | The timestamp that denotes when the session will end. After this point, the session cannot be extended and the user must be redirected to login.              |
| `session.ends_in_seconds`             | The number of seconds until `session.ends_at`.                                                                                                                |
| `session.timeout_at`                  | The timestamp that denotes when the session will time out. The zero-value, `0001-01-01T00:00:00Z`, means no timeout.                                          |
| `session.timeout_in_seconds`          | The number of seconds until `session.timeout_at`. A value of `-1` means no timeout.                                                                           |
| `tokens.expire_at`                    | The timestamp that denotes when the tokens within the session will expire.                                                                                    |
| `tokens.expire_in_seconds`            | The number of seconds until `tokens.expire_at`.                                                                                                               |
| `tokens.refreshed_at`                 | The timestamp that denotes when the tokens within the session was last refreshed.                                                                             |

If the `session.refresh` flag is enabled, the metadata response will contain a few additional fields:

#### Request:

```
GET /oauth2/session
```

#### Response:

```
HTTP/2 200 OK
Content-Type: application/json
```

```json
{
  "session": {
    ...
  },
  "tokens": {
    ...
    "next_auto_refresh_in_seconds": -1,
    "refresh_cooldown": false,
    "refresh_cooldown_seconds": 0
  }
}
```

(fields shown earlier are omitted from this example for brevity)

| Field                                 | Description                                                                                                                                                   |
|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `tokens.next_auto_refresh_in_seconds` | The number of seconds until the earliest time where the tokens will automatically be refreshed. A value of -1 means that automatic refreshing is not enabled. |
| `tokens.refresh_cooldown`             | A boolean indicating whether or not the refresh operation is on cooldown or not.                                                                              |
| `tokens.refresh_cooldown_seconds`     | The number of seconds until the refresh operation is no longer on cooldown.                                                                                   |

---

### `/oauth2/session/refresh`

This endpoint only exists if the `session.refresh` flag is enabled.

Perform a `POST` request from the user agent to this endpoint to manually refresh the tokens for the user's session.

The endpoint will respond with a `HTTP 401 Unauthorized` if the session is [_inactive_](sessions.md#session-inactivity).
It is otherwise equivalent to [the `/oauth2/session` endpoint](#oauth2session) described previously.

#### Request:

```
POST /oauth2/session/refresh
```

#### Response:

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
    "expire_in_seconds": 4166,
    "next_auto_refresh_in_seconds": 3866,
    "refresh_cooldown": true,
    "refresh_cooldown_seconds": 37
  }
}
```

Note that the refresh operation has a default _cooldown_ period of 1 minute, which may be shorter depending on the token lifetime
of the tokens returned by the identity provider.
The cooldown period exists to limit the amount of refresh token requests that we send to the identity provider.

A refresh is only triggered if `tokens.refresh_cooldown` is `false`. Requests to the endpoint are idempotent while the cooldown is active.
