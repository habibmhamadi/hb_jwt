from odoo import http, _
from odoo.http import request, Response
import jwt, secrets, hashlib
from datetime import datetime, timedelta, timezone
import json
from odoo.addons.hb_jwt.controllers.helpers import CONTENT_TYPE, STATUS_OK, GET_PARAMS, POST_PARAMS, STATUS_ERROR, STATUS_UNAUTHORIZED
from odoo.exceptions import ValidationError

# ------------------------------------------------------------ Utilities ------------------------------------------------------------
def _param(key, default=None):
    return request.env["ir.config_parameter"].sudo().get_param(key, default)

def _jwt_now():
    return datetime.now()

def _get_jwt_settings():
    ttl = int(_param("jwt.ttl_seconds", "1296000")) # 15 days
    secret = _param("jwt.secret", "mysecret!")
    return {"alg": 'HS256', "ttl": ttl, "secret": secret}
   

def _encode_jwt(uid, login):
    s = _get_jwt_settings()
    now = _jwt_now()
    user = request.env["res.users"].sudo().browse(int(uid))
    wd = user.write_date
    pwdv = int(wd.timestamp()) if wd else int(now.timestamp())
    payload = {
        "sub": str(uid),
        "login": login,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=s["ttl"])).timestamp()),
        "iss": request.httprequest.host,
        "nbf": int(now.timestamp()),
        "pwdv": pwdv,
    }
    return jwt.encode(payload, s["secret"], algorithm="HS256")

def _decode_jwt(token):
    s = _get_jwt_settings()
    return jwt.decode(token, s["secret"], algorithms=["HS256"])

def _json_error(message, status=STATUS_ERROR):
    return Response(json.dumps({'message': message}), **CONTENT_TYPE, **STATUS_ERROR)

def _json_success(data):
    return Response(json.dumps(data), **CONTENT_TYPE, **STATUS_OK)

def _get_bearer_token():
    auth = request.httprequest.headers.get("Authorization", "")
    return None if not auth.startswith("Bearer ") else auth.split(" ", 1)[1].strip()

def _jwt_authenticate():
    token = _get_bearer_token()
    if not token:
        raise ValidationError("Missing Bearer token")
    try:
        payload = _decode_jwt(token)
    except jwt.ExpiredSignatureError:
        raise ValidationError("Token expired")
    except jwt.InvalidTokenError:
        raise ValidationError("Invalid token")

    uid = payload.get("sub")
    if not uid:
        raise ValidationError("Invalid token payload: no subject")

    user = request.env["res.users"].sudo().browse(int(uid))
    if not user.exists() or not user.active:
        raise ValidationError("User inactive or not found")

    wd = user.write_date
    if wd and int(wd.timestamp()) > int(payload.get("pwdv", 0)):
        raise ValidationError("Access token outdated (password changed)")

    return int(uid), payload

def _as_user_env(uid):
    return request.env(user=uid)

# ------------------------------------------------------------ Refresh token helpers ---------------------------------------------------
def _refresh_ttl_days():
    return int(_param("jwt.refresh_ttl_days", "30"))

def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def _new_refresh_token_string() -> str:
    return secrets.token_urlsafe(48)

def _client_fingerprint():
    h = request.httprequest.headers
    ua = h.get("User-Agent", "")
    ip = request.httprequest.headers.get("X-Forwarded-For") or request.httprequest.remote_addr or ""
    return ua[:250], ip[:100]

# ------------------------------------------------------------ Controllers ------------------------------------------------------------
class JwtApiController(http.Controller):
    # CORS preflight (adjust origin as needed)
    @http.route("/api/*", **GET_PARAMS)
    def api_options(self, **kwargs):
        resp = request.make_response("", headers={
            "Access-Control-Allow-Origin": request.httprequest.headers.get("Origin", "*"),
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Authorization,Content-Type",
            "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
        })
        return resp

    # ------------------------------------------------------------ Login (returns access + refresh) -------------------------------------
    @http.route("/api/auth/login", **POST_PARAMS)
    def api_login(self, **kwargs):
        params = json.loads(request.httprequest.data or "{}") or {}
        login = (params.get("login") or "").strip()
        password = params.get("password") or ""
        db = request.env.cr.dbname

        if not login or not password:
            return _json_error("login and password are required")
        try:
            user = request.session.authenticate(db, {'login': login, 'password': password, 'type': 'password'})
            uid = user.get('uid')

            access_token = _encode_jwt(uid, login)

            # Issue refresh token (opaque, stored hashed)
            raw_refresh = _new_refresh_token_string()
            ua, ip = _client_fingerprint()
            request.env["jwt.refresh.token"].create_token(
                request.env["res.users"].sudo().browse(uid),
                _hash_token(raw_refresh),
                _refresh_ttl_days(),
                ua=ua, ip=ip,
            )

            result = {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": int(_param("jwt.ttl_seconds", "1296000")),
                "refresh_token": raw_refresh,
                "refresh_expires_in_days": _refresh_ttl_days(),
                "user": {"id": uid, "login": login},
            }
            return _json_success(result)
        except Exception as e:
            if type(e) == http.AccessDenied:
                return _json_error("Invalid credentials")
            return _json_error(str(e))

    # ------------------------------------------------------------ Refresh (rotating) -----------------------------------------------
    @http.route("/api/auth/refresh", **POST_PARAMS)
    def api_refresh(self, **kwargs):
        params = json.loads(request.httprequest.data or "{}") or {}
        raw = params.get("refresh_token") or ""
        if not raw:
            return _json_error("refresh_token is required")

        token_hash = _hash_token(raw)
        now = _jwt_now()
        Refresh = request.env["jwt.refresh.token"].sudo()

        recs = Refresh.search([("token_hash", "=", token_hash)], limit=1)
        if not recs:
            return _json_error("Invalid or already rotated/expired refresh token")

        rt = recs[0]
        if rt.revoked or (rt.expires_at and now > rt.expires_at):
            return _json_error("Refresh token expired or revoked")

        user = rt.user_id
        if not user or not user.active:
            return _json_error("User inactive or not found")

        # Rotate: revoke old, issue new
        rt.revoke()
        new_raw = _new_refresh_token_string()
        ua, ip = _client_fingerprint()
        Refresh.create_token(
            user, _hash_token(new_raw), _refresh_ttl_days(), ua=ua, ip=ip, rotated_from=rt
        )

        access_token = _encode_jwt(user.id, user.login)
        result = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": int(_param("jwt.ttl_seconds", "1296000")),
            "refresh_token": new_raw,
            "refresh_expires_in_days": _refresh_ttl_days(),
            "user": {"id": user.id, "login": user.login},
        }
        return _json_success(result)

    # ------------------------------------------------------------ Logout current refresh token ---------------------------------------
    @http.route("/api/auth/logout", **POST_PARAMS)
    def api_logout(self, **kwargs):
        params = json.loads(request.httprequest.data or "{}") or {}
        raw = params.get("refresh_token") or ""
        if not raw:
            return _json_error("refresh_token is required")

        token_hash = _hash_token(raw)
        Refresh = request.env["jwt.refresh.token"].sudo()
        recs = Refresh.search([("token_hash", "=", token_hash)], limit=1)
        if recs:
            recs.revoke()
        return _json_success({})

    # ------------------------------------------------------------ Logout all sessions for the current user -----------------------
    @http.route("/api/auth/logout_all", **POST_PARAMS)
    def api_logout_all(self, **kwargs):
        try:
            uid, _payload = _jwt_authenticate()
        except Exception as e:
            return _json_error(str(e), STATUS_UNAUTHORIZED)
        request.env["jwt.refresh.token"].revoke_all_for_user(uid)
        return _json_success({})

    # ------------------------------------------------------------ Protected examples -----------------------------------------------
    @http.route("/api/me", **GET_PARAMS)
    def api_me(self, **kwargs):
        try:
            uid, payload = _jwt_authenticate()
        except Exception as e:
            return _json_error(str(e), STATUS_UNAUTHORIZED)
        env = _as_user_env(uid)
        user = env["res.users"].browse(uid)
        partner = user.partner_id
        result = {
            "id": uid, "login": user.login,
            "name": partner.name, "email": partner.email,
            "lang": user.lang, "tz": user.tz,
        }
        return _json_success(result)
