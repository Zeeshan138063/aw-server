import json
import logging
import os
from functools import wraps
from pathlib import Path

import requests
from flask import Blueprint, current_app, jsonify, request

logger = logging.getLogger(__name__)

USER_CONFIG_PATH = Path.home() / ".pcd_sync_config.json"

ENVIRONMENTS = {
    "local": "http://127.0.0.1:8005",
    "dev":   "https://api-dev.prescribingcaredirect.co.uk",
    "qa":    "https://api-qa.prescribingcaredirect.co.uk",
    "prod":  "https://api.prescribingcaredirect.co.uk",
}
_env = os.environ.get("PCD_ENV", "prod")
_base_url = os.environ.get("PCD_BASE_URL", ENVIRONMENTS.get(_env, ENVIRONMENTS["prod"])).rstrip("/")
_app_secret = os.environ.get("PCD_APP_SECRET", "ACTIVITYWATCH_APP_SECRET")

ADMIN_VERIFY_PATH = "/api/users/admin/verify"
UPDATE_EMAIL_PATH = "/api/users/update-activity-email"

pcd_blueprint = Blueprint("pcd", __name__, url_prefix="/api/0/pcd")


@pcd_blueprint.before_request
def _check_host():
    server_host = current_app.config.get("HOST", "localhost")
    req_host = request.headers.get("host", None)
    if server_host == "0.0.0.0":
        return
    if req_host is None:
        return jsonify({"message": "host header is missing"}), 400
    if req_host.split(":")[0] not in ["localhost", "127.0.0.1", server_host]:
        return jsonify({"message": "host header is invalid"}), 400


def _pcd_headers() -> dict:
    h = {"Content-Type": "application/json"}
    if _app_secret:
        h["Authorization"] = f"Bearer {_app_secret}"
    return h


def _load_config() -> dict:
    if USER_CONFIG_PATH.exists():
        try:
            return json.loads(USER_CONFIG_PATH.read_text())
        except Exception:
            pass
    return {}


def _save_config(updates: dict) -> None:
    config = _load_config()
    config.update(updates)
    USER_CONFIG_PATH.write_text(json.dumps(config, indent=2))


def _require_admin(f):
    """Checks X-PCD-Admin-Token header set by the frontend after successful verify."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-PCD-Admin-Token", "")
        if not token or token != _load_config().get("pcd_admin_session_token", ""):
            return jsonify({"error": "Unauthorized"}), 403
        return f(*args, **kwargs)
    return decorated


@pcd_blueprint.route("/verify", methods=["POST"])
def verify_admin():
    """Proxy admin credentials to PCD API. On success, store a session token locally."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    try:
        res = requests.post(
            _base_url + ADMIN_VERIFY_PATH,
            json={"username": username, "password": password},
            headers=_pcd_headers(),
            timeout=10,
        )
        if res.status_code == 200:
            import secrets
            token = secrets.token_hex(32)
            _save_config({"pcd_admin_session_token": token})
            return jsonify({"ok": True, "token": token})
        try:
            detail = res.json().get("error", "")
        except Exception:
            detail = ""
        return jsonify({"ok": False, "error": detail or "Invalid credentials"}), 403
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return jsonify({"error": "Could not reach PCD server"}), 502


@pcd_blueprint.route("/email", methods=["GET"])
@_require_admin
def get_email():
    return jsonify({"email": _load_config().get("pcd_user_email", "")})


@pcd_blueprint.route("/email", methods=["PUT"])
@_require_admin
def update_email():
    """Call PCD update-activity-email API, then update local config on success."""
    body = request.get_json(silent=True) or {}
    new_email = (body.get("new_email") or "").strip()
    if not new_email or "@" not in new_email or "." not in new_email.split("@")[-1]:
        return jsonify({"error": "Invalid email address"}), 400

    existing_email = _load_config().get("pcd_user_email") or None

    try:
        res = requests.post(
            _base_url + UPDATE_EMAIL_PATH,
            json={"existing_email": existing_email, "new_email": new_email},
            headers=_pcd_headers(),
            timeout=10,
        )
        if res.status_code == 200:
            _save_config({"pcd_user_email": new_email})
            logger.info(f"PCD user email updated: {existing_email} → {new_email}")
            return jsonify({"ok": True, "email": new_email})
        try:
            detail = res.json().get("error", "")
        except Exception:
            detail = ""
        return jsonify({"error": detail or f"PCD API error ({res.status_code})"}), res.status_code
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return jsonify({"error": "Could not reach PCD server"}), 502
