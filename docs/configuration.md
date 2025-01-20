# Configuration

Wonderwall can be configured using either command-line flags or equivalent environment variables.

To convert a flag name to an environment variable:

- Convert the flag name to uppercase.
- Replace any non-alphanumeric characters such as periods (`.`) and hyphens (`-`) with underscores (`_`):
- Prefix the result with `WONDERWALL_`.

For example:

```text
openid.client-id -> WONDERWALL_OPENID_CLIENT_ID
```

The following flags are available:

| Flag                                       | Type     | Default Value         | Description                                                                                                                                                                                                                                                                        |
|:-------------------------------------------|:---------|:----------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `auto-login`                               | boolean  | `false`               | Enforce authentication if the user does not have a valid session for all matching upstream paths. Automatically redirects HTTP navigation requests to login, otherwise responds with 401 with the Location header set.                                                             |
| `auto-login-ignore-paths`                  | strings  |                       | Comma separated list of absolute paths to ignore when `auto-login` is enabled. Supports basic wildcard matching with glob-style asterisks. Invalid patterns are ignored.                                                                                                           |
| `bind-address`                             | string   | `127.0.0.1:3000`      | Listen address for public connections.                                                                                                                                                                                                                                             |
| `cookie.prefix`                            | string   | `io.nais.wonderwall`  | Prefix for cookie names.                                                                                                                                                                                                                                                           |
| `cookie.same-site`                         | string   | `Lax`                 | SameSite attribute for session cookies. One of [Strict, Lax, None].                                                                                                                                                                                                                |
| `cookie.secure`                            | string   | `true`                | Set secure flag on session cookies. Can only be disabled when `ingress` only consist of localhost hosts. Generally, disabling this is only necessary when using Safari.                                                                                                            |
| `encryption-key`                           | string   |                       | Base64 encoded 256-bit cookie encryption key; must be identical in instances that share session store.                                                                                                                                                                             |
| `ingress`                                  | strings  |                       | Comma separated list of ingresses used to access the main application.                                                                                                                                                                                                             |
| `log-format`                               | string   | `json`                | Log format, either `json` or `text`.                                                                                                                                                                                                                                               |
| `log-level`                                | string   | `info`                | Logging verbosity level.                                                                                                                                                                                                                                                           |
| `metrics-bind-address`                     | string   | `127.0.0.1:3001`      | Listen address for metrics only.                                                                                                                                                                                                                                                   |
| `openid.acr-values`                        | string   |                       | Space separated string that configures the default security level (`acr_values`) parameter for authorization requests.                                                                                                                                                             |
| `openid.audiences`                         | strings  |                       | List of additional trusted audiences (other than the client_id) for OpenID Connect id_token validation.                                                                                                                                                                            |
| `openid.client-id`                         | string   |                       | Client ID for the OpenID client.                                                                                                                                                                                                                                                   |
| `openid.client-jwk`                        | string   |                       | JWK containing the private key for the OpenID client in string format. If configured, this takes precedence over `openid.client-secret`.                                                                                                                                           |
| `openid.client-secret`                     | string   |                       | Client secret for the OpenID client. Overridden by `openid.client-jwk`, if configured.                                                                                                                                                                                             |
| `openid.id-token-signing-alg`              | string   | `RS256`               | Expected JWA value (as defined in RFC 7518) of public keys for validating id_token signatures. This only applies where the key's `alg` header is not set.                                                                                                                          |
| `openid.post-logout-redirect-uri`          | string   |                       | URI for redirecting the user after successful logout at the Identity Provider.                                                                                                                                                                                                     |
| `openid.provider`                          | string   | `openid`              | Provider configuration to load and use, either `openid`, `azure`, `idporten`.                                                                                                                                                                                                      |
| `openid.resource-indicator`                | string   |                       | OAuth2 resource indicator to include in authorization request for acquiring audience-restricted tokens.                                                                                                                                                                            |
| `openid.scopes`                            | strings  |                       | Comma separated list of additional scopes (other than `openid`) that should be used during the login flow.                                                                                                                                                                         |
| `openid.ui-locales`                        | string   |                       | Space-separated string that configures the default UI locale (`ui_locales`) parameter for OAuth2 consent screen.                                                                                                                                                                   |
| `openid.well-known-url`                    | string   |                       | URI to the well-known OpenID Configuration metadata document.                                                                                                                                                                                                                      |
| `redis.address`                            | string   |                       | Deprecated: prefer using `redis.uri`. Address of the Redis instance (host:port). An empty value will use in-memory session storage. Does not override address set by `redis.uri`.                                                                                                  |
| `redis.connection-idle-timeout`            | int      | `0`                   | Idle timeout for Redis connections, in seconds. If non-zero, the value should be less than the client timeout configured at the Redis server. A value of -1 disables timeout. If zero, the default value from go-redis is used (30 minutes). Overrides options set by `redis.uri`. |
| `redis.password`                           | string   |                       | Password for Redis. Overrides password set by `redis.uri`.                                                                                                                                                                                                                         |
| `redis.tls`                                | boolean  | `true`                | Whether or not to use TLS for connecting to Redis. Does not override TLS config set by `redis.uri`.                                                                                                                                                                                |
| `redis.uri`                                | string   |                       | Redis URI string. An empty value will fall back to `redis-address`.                                                                                                                                                                                                                |
| `redis.username`                           | string   |                       | Username for Redis. Overrides username set by `redis.uri`.                                                                                                                                                                                                                         |
| `session.forward-auth`                     | boolean  | `false`               | Enable endpoint for forward authentication.                                                                                                                                                                                                                                        |
| `session.inactivity`                       | boolean  | `false`               | Automatically expire user sessions if they have not refreshed their tokens within a given duration.                                                                                                                                                                                |
| `session.inactivity-timeout`               | duration | `30m`                 | Inactivity timeout for user sessions.                                                                                                                                                                                                                                              |
| `session.max-lifetime`                     | duration | `10h`                 | Max lifetime for user sessions.                                                                                                                                                                                                                                                    |
| `shutdown-graceful-period`                 | duration | `30s`                 | Graceful shutdown period when receiving a shutdown signal after which the server is forcibly exited.                                                                                                                                                                               |
| `shutdown-wait-before-period`              | duration | `0s`                  | Wait period when receiving a shutdown signal before actually starting a graceful shutdown. Useful for allowing propagation of Endpoint updates in Kubernetes.                                                                                                                      |
| `sso.domain`                               | string   |                       | The domain that the session cookies should be set for, usually the second-level domain name (e.g. `example.com`).                                                                                                                                                                  |
| `sso.enabled`                              | boolean  | `false`               | Enable single sign-on mode; one server acting as the OIDC Relying Party, and N proxies. The proxies delegate most endpoint operations to the server, and only implements a reverse proxy that reads the user's session data from the shared store.                                 |
| `sso.mode`                                 | string   | `server`              | The SSO mode for this instance. Must be one of `server` or `proxy`.                                                                                                                                                                                                                |
| `sso.server-default-redirect-url`          | string   |                       | The URL that the SSO server should redirect to by default if a given redirect query parameter is invalid.                                                                                                                                                                          |
| `sso.server-url`                           | string   |                       | The URL used by the proxy to point to the SSO server instance.                                                                                                                                                                                                                     |
| `sso.session-cookie-name`                  | string   |                       | Session cookie name. Must be the same across all SSO Servers and Proxies that should share sessions.                                                                                                                                                                               |
| `upstream-host`                            | string   | `127.0.0.1:8080`      | Address of upstream host.                                                                                                                                                                                                                                                          |
| `upstream-ip`                              | string   |                       | IP of upstream host. Overrides `upstream-host` if set.                                                                                                                                                                                                                             |
| `upstream-port`                            | int      |                       | Port of upstream host. Overrides `upstream-host` if set.                                                                                                                                                                                                                           |
| `upstream-include-id-token`                | boolean  | `false`               | Include ID token in upstream requests in 'X-Wonderwall-Id-Token' header.                                                                                                                                                                                                           |

Boolean flags are by default set to `false` unless noted otherwise.

String/strings flags are by default empty unless noted otherwise.

Duration flags support [Go duration strings](https://pkg.go.dev/time#ParseDuration), e.g.`10h`, `5m`, `30s`, etc.

## Production Use

The `bind-address` configuration should be set to listen to a public interface, e.g. `0.0.0.0:3000`.
The default value only listens to the loopback interface (`127.0.0.1`), i.e. localhost - which makes it unavailable for services
outside the Kubernetes Pod.

The `encryption-key` configuration should be set.
Otherwise, a random key will be generated and used - which will not persist between restarts. Sessions will also be
rendered invalid as they're unable to be decrypted. The following command generates a suitable encryption key in the correct format:

```shell
openssl rand -base64 32
```

The `redis.uri` or `redis.address` configuration should be set. Otherwise, an in-memory store is used.
This is especially important if you're running multiple replicas of your application that should share the same
sessions.

## Modes

Wonderwall has two runtime modes, a standalone mode and a single sign-on (SSO) mode.
See the [architecture](architecture.md#modes) document for further details.

### Standalone Mode (Default)

The default configuration of Wonderwall will start in [_standalone mode_](architecture.md#standalone-mode-default).

At minimum, the following configuration must be provided when in standalone mode:

- `openid.client-id`
- `openid.client-jwk` or `openid.client-secret`
- `openid.well-known-url`
- `ingress`

### Single Sign-On (SSO) Mode

When the `sso.enabled` flag is enabled, Wonderwall will start in [_SSO mode_](architecture.md#single-sign-on-sso-mode).

There are two possible modes when in SSO mode. This is controlled with the `sso.mode` flag; the default value is
`server`.

#### SSO Server

When the `sso.enabled` flag is enabled and the `sso.mode` flag is set to `server`, Wonderwall will start
in [SSO server mode](architecture.md#sso-server).

At minimum, the following configuration must be provided when in SSO server mode:

- `openid.client-id`
- `openid.client-jwk` or `openid.client-secret`
- `openid.well-known-url`
- `ingress`
- `redis.address`
- `sso.domain`
- `sso.session-cookie-name`
- `sso.server-default-redirect-url`

You should also explicitly configure the cookie encryption key:

- `encryption-key`

### SSO Proxy

When the `sso.enabled` flag is enabled and the `sso.mode` flag is set to `proxy`, Wonderwall will start
in [SSO proxy mode](architecture.md#sso-proxy).

At minimum, the following configuration must be provided when in SSO proxy mode:

- `ingress`
- `redis.address`
- `sso.session-cookie-name`
- `sso.server-url`

You should also explicitly configure the cookie encryption key:

- `encryption-key`

This must match the key used by the SSO server.

## Configuration Flag Details

---

### `auto-login-ignore-paths`

List of paths or patterns to ignore when `auto-login` is enabled.

The paths must be absolute paths. The match patterns use glob-style matching.

<details>

<summary>Example Match Patterns (click to expand)</summary>

- `/allowed` or `/allowed/`
    - Trailing slashes in paths and patterns are effectively ignored during matching.
    - ✅ matches:
        - `/allowed`
        - `/allowed/`
    - ❌ does not match:
        - `/allowed/nope`
        - `/allowed/nope/`
- `/public/*`
    - A single asterisk after a path means any subpath _directly_ below the path, excluding itself and any nested paths.
    - ✅ matches:
        - `/public/a`
    - ❌ does not match:
        - `/public`
        - `/public/a/b`
- `/public/**`
    - Double asterisks means any subpath below the path, including itself and any nested paths.
    - ✅ matches:
        - `/public`
        - `/public/a`
        - `/public/a/b`
    - ❌ does not match:
        - `/not/public`
        - `/not/public/a`
- `/any*`
    - ✅ matches:
        - `/any`
        - `/anything`
        - `/anywho`
    - ❌ does not match:
        - `/any/thing`
        - `/anywho/mst/ve`
- `/a/*/*`
    - ✅ matches:
        - `/a/b/c`
        - `/a/bee/cee`
    - ❌ does not match:
        - `/a`
        - `/a/b`
        - `/a/b/c/d`
- `/static/**/*.js`
    - ✅ matches:
        - `/static/bundle.js`
        - `/static/min/bundle.js`
        - `/static/vendor/min/bundle.js`
    - ❌ does not match:
        - `/static`
        - `/static/some.css`
        - `/static/min`
        - `/static/min/some.css`
        - `/static/vendor/min/some.css`

</details>

---

### `openid.provider`

#### ID-porten

When the `openid.provider` flag is set to `idporten`, the following environment variables are bound to the required
`openid`
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
