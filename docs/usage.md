# Usage

The contract for using Wonderwall is fairly straightforward.

For any endpoint that requires authentication:

1. Validate the `Authorization` header, and any tokens within.
2. If the `Authorization` header is missing, redirect the user to the [login endpoint](#1-login).
3. If the JWT `access_token` in the `Authorization` header is invalid or expired, redirect the user to
   the [login endpoint](#1-login).
4. If you need to log out a user, redirect the user to the [logout endpoint](#2-logout).

Note that Wonderwall does not validate the `access_token` that is attached; this is the responsibility of the upstream application.
Wonderwall only validates the `id_token` in accordance with the OpenID Connect Core specifications.

## Scenarios

### 1. Login

When you must authenticate a user, redirect to the user to [the `/oauth2/login` endpoint](endpoints.md#oauth2login).

#### 1.1. Autologin

The `auto-login` option (disabled by default) will configure Wonderwall to automatically redirect any HTTP `GET` requests to the login endpoint if the user does not have a valid session.
It will automatically set the `redirect` parameter for logins to the URL for the original request so that the user is redirected back to their intended location after login.

You should still check the `Authorization` header for a token and validate the token.
This is especially important as auto-login will **NOT** trigger for HTTP requests that are not `GET` requests, such as `POST` or `PUT`.

To ensure smooth end-user experiences whenever their session expires, your application must thus actively validate and
properly handle such requests. For example, your application might respond with an HTTP 401 to allow frontends to
cache or store payloads before redirecting them back to the login endpoint.

### 2. Logout

When you must authenticate a user, redirect to the user to [the `/oauth2/logout` endpoint](endpoints.md#oauth2logout).

The user's session with the sidecar will be cleared, and the user will be redirected to the identity provider for
global/single-logout, if logged in with SSO (single sign-on) at the identity provider.

#### 2.1 Local Logout

If you only want to perform a _local logout_ for the user, perform a `GET` request from the user's browser / user agent to [the `/oauth2/logout/local` endpoint](endpoints.md#oauth2logoutlocal).

This will only clear the user's local session (i.e. remove the cookies) with the sidecar, without performing global logout at the identity provider.
The endpoint responds with a HTTP 204 after successful logout. It will **not** respond with a redirect.

A local logout is useful for scenarios where users frequently switch between multiple accounts.
This means that they do not have to re-enter their credentials (e.g. username, password, 2FA) between each local logout, as they still have an SSO-session logged in with the identity provider.
If the user is using a shared device with other users, only performing a local logout is thus a security risk.

**Ensure you understand the difference in intentions between the two logout endpoints. If you're unsure, use `/oauth2/logout`.**

### 3. Advanced: Session Management

See the [session management](sessions.md) page for details.
