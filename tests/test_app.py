"""Integration tests for the OpenID Connect provider Flask application."""

import base64
import json
import os
import urllib.parse

import pytest
from joserfc import jwt as jose_jwt
from joserfc.jwk import RSAKey

import app as oidc_app


def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without signature verification (for assertion helpers)."""
    payload_b64 = token.split(".")[1]
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def application(tmp_path):
    """Return a configured Flask test application with a minimal user CSV."""
    csv_file = tmp_path / "users.csv"
    csv_file.write_text("sub,name,email\nalice,Alice Smith,alice@example.com\nbob,Bob Jones,bob@example.com\n")
    oidc_app.app.config["TESTING"] = True
    oidc_app.app.config["SECRET_KEY"] = "test-secret"
    oidc_app._auth_codes.clear()
    oidc_app._access_tokens.clear()
    oidc_app.app.config["ENV_USERS_CSV"] = str(csv_file)

    import os
    old = os.environ.get("USERS_CSV")
    os.environ["USERS_CSV"] = str(csv_file)
    yield oidc_app.app
    if old is None:
        os.environ.pop("USERS_CSV", None)
    else:
        os.environ["USERS_CSV"] = old


@pytest.fixture()
def client(application):
    return application.test_client()


_AUTHORIZE_PARAMS = {
    "response_type": "code",
    "client_id": "test-client",
    "redirect_uri": "http://localhost:9999/callback",
    "scope": "openid profile email",
    "state": "mystate",
    "nonce": "mynonce",
}


def _authorize_url(extra=None):
    params = {**_AUTHORIZE_PARAMS, **(extra or {})}
    return "/authorize?" + urllib.parse.urlencode(params)


def _do_login(client, sub="alice"):
    """Complete the authorize flow for *sub* and return (code, state)."""
    resp = client.post(
        "/authorize",
        data={**_AUTHORIZE_PARAMS, "sub": sub},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = resp.headers["Location"]
    parsed = urllib.parse.urlparse(location)
    qs = urllib.parse.parse_qs(parsed.query)
    return qs["code"][0], qs.get("state", [None])[0]


# ---------------------------------------------------------------------------
# Discovery endpoint
# ---------------------------------------------------------------------------

class TestDiscovery:
    def test_returns_200(self, client):
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200

    def test_contains_required_keys(self, client):
        data = client.get("/.well-known/openid-configuration").get_json()
        for key in ("issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"):
            assert key in data, f"missing key: {key}"

    def test_code_response_type_supported(self, client):
        data = client.get("/.well-known/openid-configuration").get_json()
        assert "code" in data["response_types_supported"]


# ---------------------------------------------------------------------------
# JWKS endpoint
# ---------------------------------------------------------------------------

class TestJWKS:
    def test_returns_200(self, client):
        resp = client.get("/.well-known/jwks.json")
        assert resp.status_code == 200

    def test_has_rsa_key(self, client):
        data = client.get("/.well-known/jwks.json").get_json()
        assert len(data["keys"]) == 1
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert "n" in key and "e" in key


# ---------------------------------------------------------------------------
# Authorize endpoint — GET (login page)
# ---------------------------------------------------------------------------

class TestAuthorizeGet:
    def test_returns_login_page(self, client):
        resp = client.get(_authorize_url())
        assert resp.status_code == 200
        assert b"Alice Smith" in resp.data
        assert b"Bob Jones" in resp.data

    def test_rejects_unsupported_response_type(self, client):
        resp = client.get(_authorize_url({"response_type": "token"}))
        assert resp.status_code == 400

    def test_user_buttons_have_data_testid(self, client):
        resp = client.get(_authorize_url())
        html = resp.data.decode()
        assert 'data-testid="user-alice"' in html
        assert 'data-testid="user-bob"' in html

    def test_recent_users_section_shown_after_login(self, client):
        # First login as alice to create a recent entry
        _do_login(client, "alice")
        resp = client.get(_authorize_url())
        html = resp.data.decode()
        assert 'data-testid="recent-users"' in html

    def test_alice_appears_in_recent_after_login(self, client):
        _do_login(client, "alice")
        resp = client.get(_authorize_url())
        html = resp.data.decode()
        # recent-users section must contain alice's button
        recent_section_start = html.find('data-testid="recent-users"')
        all_section_start = html.find('data-testid="all-users"')
        recent_section = html[recent_section_start:all_section_start] if all_section_start > recent_section_start else html[recent_section_start:]
        assert 'data-testid="user-alice"' in recent_section


# ---------------------------------------------------------------------------
# Authorize endpoint — POST (user selection)
# ---------------------------------------------------------------------------

class TestAuthorizePost:
    def test_redirects_with_code_and_state(self, client):
        code, state = _do_login(client, "alice")
        assert code
        assert state == "mystate"

    def test_missing_sub_returns_400(self, client):
        resp = client.post("/authorize", data={**_AUTHORIZE_PARAMS})
        assert resp.status_code == 400

    def test_unknown_user_returns_400(self, client):
        resp = client.post("/authorize", data={**_AUTHORIZE_PARAMS, "sub": "nobody"})
        assert resp.status_code == 400

    def test_missing_redirect_uri_returns_400(self, client):
        params = {k: v for k, v in _AUTHORIZE_PARAMS.items() if k != "redirect_uri"}
        resp = client.post("/authorize", data={**params, "sub": "alice"})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------

class TestToken:
    def test_returns_tokens(self, client):
        code, _ = _do_login(client, "alice")
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _AUTHORIZE_PARAMS["redirect_uri"],
                "client_id": _AUTHORIZE_PARAMS["client_id"],
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data
        assert "id_token" in data
        assert data["token_type"] == "Bearer"

    def test_id_token_contains_sub(self, client):
        code, _ = _do_login(client, "alice")
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _AUTHORIZE_PARAMS["redirect_uri"],
                "client_id": _AUTHORIZE_PARAMS["client_id"],
            },
        )
        id_token = resp.get_json()["id_token"]
        payload = _decode_jwt_payload(id_token)
        assert payload["sub"] == "alice"

    def test_id_token_contains_nonce(self, client):
        code, _ = _do_login(client, "alice")
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _AUTHORIZE_PARAMS["redirect_uri"],
                "client_id": _AUTHORIZE_PARAMS["client_id"],
            },
        )
        payload = _decode_jwt_payload(resp.get_json()["id_token"])
        assert payload.get("nonce") == "mynonce"

    def test_invalid_code_returns_400(self, client):
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "invalid-code",
                "redirect_uri": _AUTHORIZE_PARAMS["redirect_uri"],
            },
        )
        assert resp.status_code == 400

    def test_code_can_only_be_used_once(self, client):
        code, _ = _do_login(client, "alice")
        token_params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _AUTHORIZE_PARAMS["redirect_uri"],
        }
        client.post("/token", data=token_params)
        resp2 = client.post("/token", data=token_params)
        assert resp2.status_code == 400

    def test_unsupported_grant_type(self, client):
        resp = client.post("/token", data={"grant_type": "client_credentials"})
        assert resp.status_code == 400

    def test_id_token_verifiable_with_jwks(self, client):
        code, _ = _do_login(client, "alice")
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _AUTHORIZE_PARAMS["redirect_uri"],
                "client_id": _AUTHORIZE_PARAMS["client_id"],
            },
        )
        id_token = resp.get_json()["id_token"]

        jwks_data = client.get("/.well-known/jwks.json").get_json()
        pub_key = RSAKey.import_key(jwks_data["keys"][0])
        token = jose_jwt.decode(id_token, pub_key)
        assert token.claims["sub"] == "alice"


# ---------------------------------------------------------------------------
# UserInfo endpoint
# ---------------------------------------------------------------------------

class TestUserInfo:
    def _get_access_token(self, client, sub="alice"):
        code, _ = _do_login(client, sub)
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _AUTHORIZE_PARAMS["redirect_uri"],
                "client_id": _AUTHORIZE_PARAMS["client_id"],
            },
        )
        return resp.get_json()["access_token"]

    def test_returns_user_claims(self, client):
        token = self._get_access_token(client, "alice")
        resp = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["sub"] == "alice"
        assert data["name"] == "Alice Smith"
        assert data["email"] == "alice@example.com"

    def test_invalid_token_returns_401(self, client):
        resp = client.get("/userinfo", headers={"Authorization": "Bearer invalid"})
        assert resp.status_code == 401

    def test_missing_token_returns_401(self, client):
        resp = client.get("/userinfo")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# CORS headers
# ---------------------------------------------------------------------------

class TestCORS:

    def test_token_preflight_returns_cors_headers(self, client):
        resp = client.options("/token")
        assert resp.status_code == 200
        assert resp.headers.get("Access-Control-Allow-Origin") == "*"
        assert "POST" in resp.headers.get("Access-Control-Allow-Methods", "")
        assert "auth0-client" in resp.headers.get("Access-Control-Allow-Headers", "")


# ---------------------------------------------------------------------------
# Home page
# ---------------------------------------------------------------------------

class TestHomePage:
    def test_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_contains_title(self, client):
        resp = client.get("/")
        assert b"Insecure OpenID Provider" in resp.data

    def test_no_from_notice_by_default(self, client):
        resp = client.get("/")
        assert b'data-testid="from-notice"' not in resp.data

    def test_from_notice_shown_when_param_present(self, client):
        resp = client.get("/?from=http%3A%2F%2Flocalhost%2Funknown")
        html = resp.data.decode()
        assert 'data-testid="from-notice"' in html
        assert "http://localhost/unknown" in html


# ---------------------------------------------------------------------------
# Unknown-URL redirect to home page
# ---------------------------------------------------------------------------

class TestUnknownUrlRedirect:
    def test_unknown_path_redirects_to_home(self, client):
        resp = client.get("/this/path/does/not/exist", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"].startswith("/")
        assert "from=" in resp.headers["Location"]

    def test_redirect_follows_to_home_with_notice(self, client):
        resp = client.get("/no-such-endpoint", follow_redirects=True)
        assert resp.status_code == 200
        html = resp.data.decode()
        assert 'data-testid="from-notice"' in html
        assert "no-such-endpoint" in html


# ---------------------------------------------------------------------------
# Signing key persistence
# ---------------------------------------------------------------------------

class TestSigningKeyPersistence:
    def setup_method(self):
        oidc_app._signing_key.cache_clear()

    def teardown_method(self):
        oidc_app._signing_key.cache_clear()

    def test_generates_and_saves_key_file(self, tmp_path, monkeypatch):
        key_file = str(tmp_path / "signing_key.json")
        monkeypatch.setenv("SIGNING_KEY_FILE", key_file)
        key = oidc_app._signing_key()
        assert key is not None
        assert os.path.isfile(key_file)
        with open(key_file) as f:
            data = json.load(f)
        assert data.get("kty") == "RSA"
        assert "d" in data  # private component must be present

    def test_loads_existing_valid_key(self, tmp_path, monkeypatch):
        key_file = str(tmp_path / "signing_key.json")
        monkeypatch.setenv("SIGNING_KEY_FILE", key_file)
        # Generate and save a key
        key1 = oidc_app._signing_key()
        kid1 = key1.kid
        # Clear cache and reload — should return the same key id
        oidc_app._signing_key.cache_clear()
        key2 = oidc_app._signing_key()
        assert key2.kid == kid1

    def test_regenerates_key_when_file_contains_invalid_json(self, tmp_path, monkeypatch):
        key_file = str(tmp_path / "signing_key.json")
        key_file_path = tmp_path / "signing_key.json"
        key_file_path.write_text("not valid json {{{{")
        monkeypatch.setenv("SIGNING_KEY_FILE", key_file)
        key = oidc_app._signing_key()
        assert key is not None
        # The file should be overwritten with a valid key
        with open(key_file) as f:
            data = json.load(f)
        assert data.get("kty") == "RSA"

    def test_regenerates_key_when_file_contains_invalid_key_data(self, tmp_path, monkeypatch):
        key_file = str(tmp_path / "signing_key.json")
        (tmp_path / "signing_key.json").write_text(json.dumps({"kty": "RSA", "n": "bad"}))
        monkeypatch.setenv("SIGNING_KEY_FILE", key_file)
        key = oidc_app._signing_key()
        assert key is not None

    def test_continues_in_memory_when_directory_unwritable(self, monkeypatch):
        monkeypatch.setenv("SIGNING_KEY_FILE", "/nonexistent_dir_xyz/key.json")
        key = oidc_app._signing_key()
        assert key is not None
