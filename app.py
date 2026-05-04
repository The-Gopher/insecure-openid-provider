"""Insecure OpenID Connect Identity Provider.

This server is intended for automated testing only.  It deliberately omits
all security measures (no password, trivially-guessable signing key, etc.)
so that test suites can authenticate without real credentials.

Usage::

    gunicorn app:app              # uses users.csv in the current directory
    USERS_CSV=my.csv gunicorn app:app
    ISSUER=https://auth.example gunicorn app:app
"""

import json
import logging
import os
import secrets
import time
import urllib.parse
from functools import lru_cache

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import RSAKey
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from users.csv_source import CSVUserSource
from users.base import UserSource

app = Flask(__name__)
# Honor X-Forwarded-Proto/Host from a single upstream proxy that terminates TLS.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY", "insecure-testing-secret")

# ---------------------------------------------------------------------------
# In-memory stores (intentionally simple — this is a testing tool)
# ---------------------------------------------------------------------------
# authorization_code -> {sub, client_id, redirect_uri, nonce, scope, exp}
_auth_codes: dict = {}
# Kept for backward-compatibility with test fixtures; access tokens are now self-contained JWTs
_access_tokens: dict = {}

# How many recently-selected users to show at the top of the login list
RECENT_USERS_LIMIT = 5
# How long (seconds) an authorization code stays valid
AUTH_CODE_TTL = 60
# How long (seconds) an access token stays valid
ACCESS_TOKEN_TTL = 3600
# How long (seconds) an id_token stays valid
ID_TOKEN_TTL = 3600


# ---------------------------------------------------------------------------
# RSA key pair — loaded from disk (persisted) or generated once per process
# ---------------------------------------------------------------------------

_SIGNING_KEY_FILE_DEFAULT = "/data/signing_key.json"


@lru_cache(maxsize=1)
def _signing_key() -> RSAKey:
    key_file = os.environ.get("SIGNING_KEY_FILE", _SIGNING_KEY_FILE_DEFAULT)

    if os.path.isfile(key_file):
        try:
            with open(key_file) as f:
                key_data = json.load(f)
            key = RSAKey.import_key(key_data)
            key.ensure_kid()
            return key
        except (json.JSONDecodeError, ValueError, KeyError, TypeError, OSError, JoseError) as exc:
            logging.warning(
                "Signing key at %s is invalid or unreadable (%s); generating a new one.",
                key_file,
                exc,
            )

    key = RSAKey.generate_key(2048)
    key.ensure_kid()

    try:
        dir_name = os.path.dirname(os.path.abspath(key_file))
        os.makedirs(dir_name, mode=0o700, exist_ok=True)
        with open(key_file, "w") as f:
            json.dump(key.as_dict(private=True), f)
        os.chmod(key_file, 0o600)
    except OSError as exc:
        logging.warning("Could not persist signing key to %s: %s", key_file, exc)

    return key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_user_source() -> UserSource:
    csv_path = os.environ.get("USERS_CSV", "users.csv")
    return CSVUserSource(csv_path)


def _issuer() -> str:
    return os.environ.get("ISSUER", "http://localhost:5000")


def _now() -> int:
    return int(time.time())


def _purge_expired() -> None:
    now = _now()
    expired_codes = [k for k, v in _auth_codes.items() if v["exp"] < now]
    for k in expired_codes:
        del _auth_codes[k]


def _make_id_token(sub: str, client_id: str, nonce: str | None, extra_claims: dict | None = None) -> str:
    key = _signing_key()
    now = _now()
    payload = {
        "iss": _issuer(),
        "sub": sub,
        "aud": client_id,
        "iat": now,
        "exp": now + ID_TOKEN_TTL,
    }
    if nonce:
        payload["nonce"] = nonce
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode({"alg": "RS256", "kid": key.kid}, payload, key)


def _make_access_token(sub: str, scope: str) -> str:
    key = _signing_key()
    now = _now()
    payload = {
        "iss": _issuer(),
        "sub": sub,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "scope": scope,
    }
    return jwt.encode({"alg": "RS256", "kid": key.kid}, payload, key)


def _jwks_for_key() -> dict:
    jwk = _signing_key().as_dict(private=False)
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return jwk


# ---------------------------------------------------------------------------
# OpenID Connect discovery & JWKS
# ---------------------------------------------------------------------------

def external_url_for(endpoint: str) -> str:
    return url_for(endpoint, _external=True)

@app.route("/.well-known/openid-configuration", methods=["GET", "OPTIONS"])
def openid_configuration():
    if request.method == "GET":
        base = _issuer()
        response = jsonify(
            {
                "issuer": base,
                "authorization_endpoint":  external_url_for("authorize"),
                "token_endpoint": external_url_for("token"),
                "userinfo_endpoint": external_url_for("userinfo"),
                "jwks_uri": external_url_for("jwks"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "scopes_supported": ["openid", "profile", "email"],
                "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
                "claims_supported": [
                    "sub",
                    "iss",
                    "aud",
                    "iat",
                    "exp",
                    "name",
                    "email",
                    "nonce",
                ],
            }
        )
    else:
        response = app.make_default_options_response()

    headers = response.headers

    headers["Access-Control-Allow-Origin"] = "*"
    headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

    return response


@app.get("/.well-known/jwks.json")
def jwks():
    return jsonify({"keys": [_jwks_for_key()]})


# ---------------------------------------------------------------------------
# Authorize endpoint
# ---------------------------------------------------------------------------

@app.get("/authorize")
def authorize():
    response_type = request.args.get("response_type", "")
    if response_type != "code":
        return (
            jsonify({"error": "unsupported_response_type"}),
            400,
        )

    source = _get_user_source()
    all_users = source.get_users()

    # Pull recently-selected subs from the session and move them to the top
    recent_subs: list = session.get("recent_users", [])
    recent_map = {u.sub: u for u in all_users}
    recent_users = [recent_map[s] for s in recent_subs if s in recent_map]
    other_users = [u for u in all_users if u.sub not in set(recent_subs)]

    return render_template(
        "login.html",
        recent_users=recent_users,
        other_users=other_users,
        params=request.args.to_dict(),
    )


@app.post("/authorize")
def authorize_submit():
    sub = request.form.get("sub")
    client_id = request.form.get("client_id", "")
    redirect_uri = request.form.get("redirect_uri", "")
    state = request.form.get("state", "")
    nonce = request.form.get("nonce", "")
    scope = request.form.get("scope", "openid")

    if not sub:
        return jsonify({"error": "missing sub"}), 400

    source = _get_user_source()
    user = source.get_user(sub)
    if user is None:
        return jsonify({"error": "unknown user"}), 400

    if not redirect_uri:
        return jsonify({"error": "missing redirect_uri"}), 400

    # Record selection in the session for the "recently used" list
    recent: list = session.get("recent_users", [])
    if sub in recent:
        recent.remove(sub)
    recent.insert(0, sub)
    session["recent_users"] = recent[:RECENT_USERS_LIMIT]

    # Issue an authorization code
    _purge_expired()
    code = secrets.token_urlsafe(24)
    _auth_codes[code] = {
        "sub": sub,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "nonce": nonce or None,
        "scope": scope,
        "exp": _now() + AUTH_CODE_TTL,
    }

    # Validate redirect_uri has an acceptable scheme before redirecting.
    # (This is an intentionally open provider so we only enforce basic URL sanity.)
    parsed = urllib.parse.urlparse(redirect_uri)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "invalid_redirect_uri"}), 400

    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}"
    if state:
        location += f"&state={state}"
    return redirect(location)


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------


@app.route("/oauth/token", methods=["GET", "POST", "OPTIONS"])
def token():
    _purge_expired()

    if request.method == "POST":

        grant_type = request.form.get("grant_type", "")
        if grant_type != "authorization_code":
            return jsonify({"error": "unsupported_grant_type"}), 400

        code = request.form.get("code", "")
        redirect_uri = request.form.get("redirect_uri", "")

        code_data = _auth_codes.pop(code, None)
        if code_data is None:
            return jsonify({"error": "invalid_grant"}), 400

        if code_data["exp"] < _now():
            return (
                jsonify(
                    {"error": "invalid_grant", "error_description": "code expired"}
                ),
                400,
            )

        if redirect_uri and code_data["redirect_uri"] != redirect_uri:
            return (
                jsonify(
                    {
                        "error": "invalid_grant",
                        "error_description": "redirect_uri mismatch",
                    }
                ),
                400,
            )

        sub = code_data["sub"]
        scope = code_data["scope"]

        source = _get_user_source()
        user = source.get_user(sub)
        extra = user.claims() if user else {}
        extra.pop("sub", None)

        id_token = _make_id_token(
            sub, code_data["client_id"], code_data["nonce"], extra
        )
        access_token = _make_access_token(sub, scope)

        response = jsonify(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL,
                "id_token": id_token,
                "scope": scope,
            }
        )
    else:
        response = app.make_default_options_response()

    # Allow CORS preflight requests to the token endpoint, which is commonly used in testing scenarios.
    headers = response.headers

    headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    headers["Access-Control-Allow-Credentials"] = "true"
    headers["Access-Control-Allow-Headers"] = (
        "Content-Type, Authorization, auth0-client"
    )
    headers["Vary"] = "Origin"

    return response

# ---------------------------------------------------------------------------
# UserInfo endpoint
# ---------------------------------------------------------------------------

@app.get("/userinfo")
@app.post("/userinfo")
def userinfo():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        bearer = auth_header[7:].strip()
    else:
        bearer = request.form.get("access_token", "") or request.args.get("access_token", "")

    if not bearer:
        return jsonify({"error": "unauthorized"}), 401

    try:
        key = _signing_key()
        token_obj = jwt.decode(bearer, key)
        claims = token_obj.claims
        if claims.get("exp", 0) < _now():
            return jsonify({"error": "invalid_token"}), 401
        sub = claims["sub"]
    except (JoseError, KeyError, ValueError) as exc:
        logging.debug("Access token validation failed: %s: %s", type(exc).__name__, exc)
        return jsonify({"error": "invalid_token"}), 401

    source = _get_user_source()
    user = source.get_user(sub)
    if user is None:
        return jsonify({"error": "unknown_user"}), 404

    return jsonify(user.claims())


# ---------------------------------------------------------------------------
# Home page
# ---------------------------------------------------------------------------

@app.get("/")
def home():
    from_url = request.args.get("from_url")
    return render_template("home.html", from_url=from_url)


# ---------------------------------------------------------------------------
# Catch-all — redirect unknown paths to home with the original URL
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(exc):
    original = request.url
    return redirect(url_for("home", from_url=original))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    port = int(os.environ.get("FLASK_PORT", 6000))
    app.run(debug=debug, port=port)