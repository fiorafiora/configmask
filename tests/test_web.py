"""HTTP flow: login, shared mapping, encryption, restore warnings, delete."""

import logging
import re
import sqlite3

from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from app.crypto import Vault
from app.db import checkpoint, counts_for_session
from app.main import create_app
from app.settings import Settings, hash_password

PASSWORD = "test-password-1"
SECRET = "test-secret-key-0123456789"
MARKER_SECRET = "FAKESECRET_DBCHECK_NORTH_UNIQUE"
MARKER_HOST = "UNIQUEHOST123"
MARKER_IP = "10.44.55.66"

_CSRF = re.compile(r'name="csrf" value="([^"]+)"')


def _settings(tmp_path, limit: int = 10 * 1024 * 1024) -> Settings:
    salt = b"0123456789abcdef0123456789abcdef"
    return Settings(
        password_hash=hash_password(PASSWORD, salt),
        password_salt=salt,
        secret_key=SECRET,
        fernet_key=Fernet.generate_key().decode(),
        db_path=str(tmp_path / "configmask.db"),
        cookie_secure=False,
        max_upload_bytes=limit,
        port=8741,
    )


def _csrf(html: str) -> str:
    match = _CSRF.search(html)
    assert match, html[:400]
    return match.group(1)


def _login(client: TestClient) -> None:
    page = client.get("/login")
    assert page.status_code == 200
    response = client.post(
        "/login",
        data={"password": PASSWORD, "csrf": _csrf(page.text), "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def _open_session(client: TestClient, description: str = "Cedar lab change") -> str:
    home = client.get("/")
    assert home.status_code == 200
    created = client.post(
        "/sessions",
        data={"csrf": _csrf(home.text), "description": description, "vendor": "cisco_ios"},
        follow_redirects=False,
    )
    assert created.status_code == 303
    location = created.headers["location"]
    assert location.startswith("/sessions/")
    return location.split("?")[0]


def _config(host: str, address: str, secret: str) -> str:
    return (
        f"hostname {host}\n"
        "!\n"
        f"enable secret 0 {secret}\n"
        "!\n"
        "interface GigabitEthernet0/0\n"
        f" ip address {address} 255.255.255.0\n"
        "!\n"
    )


def test_login_sanitize_restore_and_delete(tmp_path):
    settings = _settings(tmp_path)
    client = TestClient(create_app(settings))
    health = client.get("/health")
    assert health.json() == {"status": "ok"}
    assert client.get("/docs", follow_redirects=False).status_code == 404
    assert client.get("/", follow_redirects=False).status_code == 303

    _login(client)
    bad = client.post("/logout", data={"csrf": "nope"}, follow_redirects=False)
    assert bad.status_code == 303
    assert client.get("/").status_code == 200

    blank = client.post(
        "/sessions",
        data={"csrf": _csrf(client.get("/").text), "description": "   ", "vendor": "cisco_ios"},
        follow_redirects=False,
    )
    assert blank.status_code == 303
    assert "description" in blank.headers["location"]

    session_path = _open_session(client, "Northwind Cedar firewall change")
    opened = client.get(session_path)
    assert "JOB-0001" in opened.text
    assert "Northwind Cedar firewall change" in opened.text
    page = client.get(session_path)
    token = _csrf(page.text)
    keywords = client.post(
        f"{session_path}/keywords",
        data={"csrf": token, "keywords": "Northwind\nCedar\n"},
        follow_redirects=False,
    )
    assert keywords.status_code == 303

    page = client.get(session_path)
    first = client.post(
        f"{session_path}/sanitize",
        data={
            "csrf": _csrf(page.text),
            "label": "edge-a",
            "config_text": _config("EDGE-NORTH-01", "10.44.55.66", MARKER_SECRET)
            + "interface GigabitEthernet0/1\n ip address 10.44.55.1 255.255.255.0\n",
        },
        follow_redirects=False,
    )
    assert first.status_code == 303
    config_path = first.headers["location"].split("?")[0]
    stored = client.get(config_path)
    assert stored.status_code == 200
    assert MARKER_SECRET not in stored.text
    assert MARKER_HOST not in stored.text
    assert "10.44.55." not in stored.text
    assert "&lt;REMOVED&gt;" in stored.text or "<REMOVED>" in stored.text

    download = client.get(f"{config_path}/download?which=sanitized")
    assert download.status_code == 200
    assert MARKER_SECRET not in download.text
    assert "<REMOVED>" in download.text
    original = client.get(f"{config_path}/download?which=original")
    assert MARKER_SECRET in original.text

    page = client.get(session_path)
    second = client.post(
        f"{session_path}/sanitize",
        data={
            "csrf": _csrf(page.text),
            "label": "edge-b",
            "config_text": _config("EDGE-NORTH-02", "10.44.55.2", "FAKESECRET_OTHER"),
        },
        follow_redirects=False,
    )
    assert second.status_code == 303
    second_body = client.get(second.headers["location"].split("?")[0] + "/download?which=sanitized")
    first_ip = re.search(r"ip address (\d+\.\d+\.\d+\.66)", download.text)
    second_ip = re.search(r"ip address (\d+\.\d+\.\d+\.2)", second_body.text)
    assert first_ip and second_ip
    assert first_ip.group(1).rsplit(".", 1)[0] == second_ip.group(1).rsplit(".", 1)[0]
    assert first_ip.group(1).endswith(".66")
    assert second_ip.group(1).endswith(".2")

    mapping = client.get(session_path)
    assert "10.44.55.66" in mapping.text
    assert MARKER_SECRET not in mapping.text
    assert "EDGE-NORTH-01" in mapping.text

    edited = download.text + "\nip route 203.0.113.50 255.255.255.255 10.250.9.9\nhostname HOST-999\n"
    restore_page = client.get(f"{session_path}/restore")
    config_id = config_path.rstrip("/").split("/")[-1]
    restored = client.post(
        f"{session_path}/restore",
        data={
            "csrf": _csrf(restore_page.text),
            "compare_config_id": config_id,
            "config_text": edited,
        },
        follow_redirects=True,
    )
    assert restored.status_code == 200
    assert "not in the session mapping" in restored.text
    assert "Do not paste" in restored.text
    assert "HOST-999" in restored.text
    assert "diff-row" in restored.text
    assert "10.44.55.66" in restored.text

    home = client.get("/")
    deleted = client.post(
        f"{session_path}/delete",
        data={"csrf": _csrf(home.text)},
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert client.get(session_path).status_code == 404
    session_id = int(session_path.rstrip("/").split("/")[-1])
    assert counts_for_session(settings.db_path, session_id) == {
        "mappings": 0,
        "configs": 0,
        "restores": 0,
    }


def test_mapping_and_configs_are_encrypted_at_rest(tmp_path, caplog):
    settings = _settings(tmp_path)
    caplog.set_level(logging.INFO, logger="configmask")
    client = TestClient(create_app(settings))
    _login(client)
    session_path = _open_session(client, "UNIQUECLIENTCHANGE")
    page = client.get(session_path)
    text = (
        f"hostname {MARKER_HOST}\n"
        f"enable secret 0 {MARKER_SECRET}\n"
        "interface GigabitEthernet0/0\n"
        f" description Northwind closet\n"
        f" ip address {MARKER_IP} 255.255.255.0\n"
    )
    response = client.post(
        f"{session_path}/sanitize",
        data={"csrf": _csrf(page.text), "label": "dbcheck", "config_text": text},
        follow_redirects=False,
    )
    assert response.status_code == 303
    checkpoint(settings.db_path)
    blob = (tmp_path / "configmask.db").read_bytes()
    wal = tmp_path / "configmask.db-wal"
    if wal.exists():
        blob += wal.read_bytes()
    assert MARKER_SECRET.encode() not in blob
    assert MARKER_HOST.encode() not in blob
    assert MARKER_IP.encode() not in blob
    assert b"Northwind closet" not in blob
    assert b"UNIQUECLIENTCHANGE" not in blob

    vault = Vault(settings.fernet_key)
    with sqlite3.connect(settings.db_path) as conn:
        row = conn.execute("SELECT real_enc, placeholder_enc FROM mappings LIMIT 1").fetchone()
    assert row is not None
    assert row[0] != vault.decrypt(row[0]).encode()
    assert vault.decrypt(row[0])
    joined = "\n".join(record.getMessage() for record in caplog.records)
    assert MARKER_SECRET not in joined
    assert MARKER_HOST not in joined
    assert MARKER_IP not in joined
    assert "sanitize" in joined


def test_upload_limit_and_bad_password(tmp_path):
    settings = _settings(tmp_path, limit=80)
    client = TestClient(create_app(settings))
    page = client.get("/login")
    bad = client.post(
        "/login",
        data={"password": "wrong-password", "csrf": _csrf(page.text), "next": "/"},
        follow_redirects=False,
    )
    assert bad.status_code == 303
    assert "bad_login" in bad.headers["location"]

    _login(client)
    session_path = _open_session(client, "Upload limit check")
    page = client.get(session_path)
    too_big = client.post(
        f"{session_path}/sanitize",
        data={"csrf": _csrf(page.text), "label": "big", "config_text": "hostname EDGE\n" + ("!\n" * 80)},
        follow_redirects=False,
    )
    assert too_big.status_code == 303
    assert "too_large" in too_big.headers["location"]

    offline = client.get("/login")
    assert "fonts.googleapis" not in offline.text
    assert "cdn" not in offline.text.casefold()
    css = client.get("/static/app.css")
    assert css.status_code == 200
    assert "http://" not in css.text and "https://" not in css.text
