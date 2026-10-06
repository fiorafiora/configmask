from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.auth import LoginGuard
from app.crypto import Vault
from app.db import init_db
from app.logging_config import setup_logging
from app.settings import Settings
from app.web.routes import router

_STATIC = Path(__file__).resolve().parent / "web" / "static"


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                extra = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"content-security-policy": (
                        b"default-src 'self'; style-src 'self'; script-src 'self'; "
                        b"img-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'"
                    ),
                    b"cache-control": b"no-store",
                }
                existing = {key.lower() for key, _value in headers}
                for key, value in extra.items():
                    if key not in existing:
                        headers.append((key, value))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    setup_logging()
    init_db(settings.db_path)
    app = FastAPI(title="ConfigMask", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.vault = Vault(settings.fernet_key)
    app.state.login_guard = LoginGuard()
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie="configmask",
        max_age=12 * 60 * 60,
        same_site="strict",
        https_only=settings.cookie_secure,
    )
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
    app.include_router(router)
    return app


if os.environ.get("CONFIGMASK_SKIP_APP") != "1":
    app = create_app()
else:
    app = None  # type: ignore[assignment]
