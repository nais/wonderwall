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

The `auto-login` option will configure Wonderwall to enforce authentication for **all** requests, except for the paths that are explicitly [excluded](configuration.md#auto-login-ignore-paths).

If the user is _unauthenticated_ or has an [_inactive_ or _expired_ session](sessions.md), all requests will be short-circuited (i.e. return early and **not** proxied to your application).
The short-circuited response depends on whether the request is a _top-level navigation_ request or not.

A _top-level navigation request_ is a `GET` request that has the [Fetch metadata request headers](https://developer.mozilla.org/en-US/docs/Glossary/Fetch_metadata_request_header) `Sec-Fetch-Dest=document` and `Sec-Fetch-Mode=navigate`.
If the user agent does not support the Fetch metadata headers, we look for an `Accept` header that includes `text/html`, which all major browsers send for navigation requests.
Internet Explorer 8 won't work with this of course, so hopefully you're not in a position that requires supporting this browser.

A top-level navigation request results in a HTTP 302 Found response with the `Location` header pointing to [the `/oauth2/login` endpoint](endpoints.md#oauth2login).
The `redirect` parameter in the login URL is set to the value found in the `Referer` header, so that the user is redirected back to their intended location after login.
If the `Referer` header is empty, the `redirect` parameter is set to the matching ingress path for the original request.

Other requests are considered non-navigational requests and result in a HTTP 401 Unauthorized response with the `Location` header set as described above.

For defence in depth, you should still check the `Authorization` header for a token and validate the token even when using auto-login.

### 2. Logout

When you must log out a user, redirect to the user to [the `/oauth2/logout` endpoint](endpoints.md#oauth2logout).

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
