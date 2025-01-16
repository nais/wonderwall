# Session Management

When a user authenticates themselves, they receive a session. Sessions are stored server-side; we only store a session identifier at the end-user's user agent.

A session has three states:

- _active_ - the session is valid
- _inactive_ - the session has reached the _inactivity timeout_ and is considered invalid
- _expired_ - the session has reached its _maximum lifetime_ and is considered invalid

Requests with an _invalid_ session are considered _unauthenticated_.

## Session Metadata

User agents can access their own session metadata by using [the `/oauth2/session` endpoint](endpoints.md#oauth2session).

## Session Expiry

Every session has a maximum lifetime. 
The lifetime is indicated by the `session.ends_at` and `session.ends_in_seconds` fields in the session metadata.

When the session reaches the maximum lifetime, it is considered to be _expired_, after which the user is essentially unauthenticated.
A new session must be acquired by redirecting the user to [the `/oauth2/login` endpoint](endpoints.md#oauth2login) again.

The maximum lifetime can be configured with the `session.max-lifetime` flag.

## Session Refreshing

The tokens within the session will usually expire before the session itself.
This is indicated by the `tokens.expire_at` and `tokens.expire_in_seconds` fields in the session metadata.

If you've configured a session lifetime that is longer than the token expiry, you'll probably want to _refresh_ the tokens to avoid redirecting end-users to the `/oauth2/login` endpoint whenever the access tokens have expired.

### Automatic vs Manual Refresh

The behaviour for refreshing depends on the [runtime mode](configuration.md#modes) for Wonderwall.

In standalone mode, tokens are automatically refreshed. 
Tokens will at the _earliest_ automatically be renewed 5 minutes before they expire.
If the token already _has_ expired, a refresh attempt is still automatically triggered as long as the session itself not has ended or is marked as inactive.

Automatic refreshes happens whenever the end-user visits or requests any path that is proxied to the upstream application.

In SSO mode, tokens can not be automatically refreshed. They must be refreshed by performing a request to [the `/oauth2/session/refresh` endpoint](endpoints.md#oauth2sessionrefresh).

## Session Inactivity

A session can be marked as _inactive_ before it _expires_ (reaches the maximum lifetime).
This happens if the time since the last _refresh_ exceeds the given _inactivity timeout_.

An _inactive_ session _cannot_ be refreshed; a new session must be acquired by redirecting the user to the `/oauth2/login` endpoint.
This is useful if you want to ensure that an end-user can re-authenticate with the identity provider if they've been gone from an authenticated session for some time.

Inactivity support is enabled with the `session.inactivity` option.

The activity state of the session is indicated by the `session.active` field in the session metadata.

The time until the session will be marked as inactive are indicated by the `session.timeout_at` and `session.timeout_in_seconds` fields in the session metadata.

The timeout is configured with `session.inactivity-timeout`.
If this timeout is shorter than the token expiry, the session metadata fields `tokens.expire_at` and `tokens.expire_in_seconds` will be reduced accordingly to reflect the inactivity timeout.
