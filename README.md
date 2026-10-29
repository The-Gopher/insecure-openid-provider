# insecure-openid-provider
A OpenID IDP for testing.

## Native apps

Auth0's native SDKs (e.g. `react-native-auth0`) work against this provider when they are pointed at
its host as the Auth0 domain:

- **Custom-scheme redirects.** `redirect_uri` may be `http`, `https`, or a reverse-DNS private-use
  scheme as in RFC 8252 §7.1 (`com.example.app.auth0://…`). A scheme without a period, such as
  `javascript:` or `myapp:`, is rejected.
- **JSON token requests.** `/oauth/token` accepts a JSON body as well as a form. PKCE parameters are
  accepted and ignored.
- **Refresh tokens.** A scope containing `offline_access` returns a `refresh_token`, which the
  `refresh_token` grant exchanges for new access and id tokens. Like Auth0 without rotation, the
  refresh response carries no new refresh token. Refresh tokens never expire and are held in
  memory, so a restart invalidates them.
- **`/v2/logout`.** Auth0's logout path clears the login and redirects to `returnTo`, which must pass
  the same scheme check as `redirect_uri`.

The SDKs check that the id token's `iss` is `https://<domain>/`, so set `ISSUER` to the host the
app is configured with.
