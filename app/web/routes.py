from __future__ import annotations

import hmac
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response
from starlette.templating import Jinja2Templates

from app.db import (
    create_session,
    delete_session,
    get_config,
    get_restore,
    get_session_row,
    list_configs,
    list_mapping_rows,
    list_restores,
    list_sessions,
    load_keywords,
    load_mapper,
    read_description,
    save_keywords,
    update_description,
)
from app.engine.registry import UnknownVendor, get_vendor
from app.keywords import parse_keywords
from app.services import (
    ConfigError,
    build_restore,
    decode_config,
    review_restore,
    safe_filename,
    safe_label,
    sanitize_upload,
    type_label,
)

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
router = APIRouter()

_ERRORS = {
    "bad_login": "That password does not match.",
    "locked": "Too many attempts. Wait a minute, then try again.",
    "description": "Add a short description of the customer or change, up to 160 characters.",
    "empty": "Paste a configuration or choose a file.",
    "too_large": "That configuration is over the upload limit.",
    "csrf": "The form expired. Refresh the page and try again.",
    "keywords": "A keyword was rejected. Use a client or site name, at least 3 characters, not an IOS command.",
    "pool": "The stand-in address pools cannot fit a network in this configuration.",
    "missing": "That session or file is no longer here.",
    "vendor": "That ruleset is not available.",
}
_NOTICES = {
    "created": "Session opened. The job code is assigned. Add site keywords, then upload each device.",
    "description": "Description saved.",
    "keywords": "Keyword list saved. It applies to the next upload.",
    "deleted": "Session deleted. Its mapping and stored configs are gone.",
    "sanitized": "Sanitized copy is ready. Share only this file.",
}


def _safe_next(path: str) -> str:
    if not path.startswith("/") or path.startswith("//") or "\\" in path:
        return "/"
    return path


def _ensure_csrf(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def _csrf_ok(request: Request, form) -> bool:
    expected = request.session.get("csrf") or ""
    supplied = str(form.get("csrf") or "")
    if not expected or not supplied:
        return False
    return hmac.compare_digest(supplied, expected)


def _ctx(request: Request, **extra):
    code = request.query_params.get("error", "")
    notice = request.query_params.get("notice", "")
    base = {
        "csrf": _ensure_csrf(request),
        "user": request.session.get("user"),
        "error": _ERRORS.get(code, ""),
        "notice": _NOTICES.get(notice, ""),
    }
    base.update(extra)
    return base


def _render(request: Request, name: str, status_code: int = 200, **extra):
    return _TEMPLATES.TemplateResponse(request, name, _ctx(request, **extra), status_code=status_code)


def _logged_in(request: Request) -> bool:
    return request.session.get("user") == "admin"


def clean_description(value: str) -> str:
    text = " ".join(str(value or "").split())
    if not text or len(text) > 160 or any(ord(ch) < 32 for ch in text):
        raise ConfigError("description")
    return text


def _show_session(vault, row: dict | None) -> dict | None:
    if row is None:
        return None
    shown = dict(row)
    shown["description"] = read_description(vault, shown)
    return shown


def _login_redirect(request: Request) -> RedirectResponse:
    return RedirectResponse(f"/login?next={quote(_safe_next(request.url.path))}", status_code=303)


async def _payload(request: Request, form) -> tuple[str, str]:
    settings = request.app.state.settings
    upload = form.get("config_file")
    paste = str(form.get("config_text") or "")
    filename = "pasted.cfg"
    data = b""
    if upload is not None and getattr(upload, "filename", ""):
        data = await upload.read()
        filename = safe_filename(upload.filename)
    if data:
        text = decode_config(data, settings.max_upload_bytes)
    else:
        if len(paste.encode("utf-8")) > settings.max_upload_bytes:
            raise ConfigError("too_large")
        text = paste
    if not text.strip():
        raise ConfigError("empty")
    return text, filename


def _too_big(request: Request) -> bool:
    raw = request.headers.get("content-length")
    if not raw:
        return False
    try:
        size = int(raw)
    except ValueError:
        return False
    return size > request.app.state.settings.max_upload_bytes + 65536


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/login")
def login_form(request: Request):
    if _logged_in(request):
        return RedirectResponse(_safe_next(request.query_params.get("next", "/")), status_code=303)
    return _render(request, "login.html", next_path=_safe_next(request.query_params.get("next", "/")))


@router.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    nxt = _safe_next(str(form.get("next") or "/"))
    if not _csrf_ok(request, form):
        return RedirectResponse("/login?error=csrf", status_code=303)
    guard = request.app.state.login_guard
    if not guard.allowed():
        return RedirectResponse("/login?error=locked", status_code=303)
    password = str(form.get("password") or "")
    if not request.app.state.settings.verify_password(password):
        guard.record_failure()
        return RedirectResponse(f"/login?error=bad_login&next={quote(nxt)}", status_code=303)
    guard.record_success()
    request.session.clear()
    request.session["user"] = "admin"
    request.session["csrf"] = secrets.token_urlsafe(32)
    return RedirectResponse(nxt, status_code=303)


@router.post("/logout")
async def logout(request: Request):
    form = await request.form()
    if _csrf_ok(request, form):
        request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/")
def session_list(request: Request):
    if not _logged_in(request):
        return _login_redirect(request)
    sessions = list_sessions(request.app.state.settings.db_path, request.app.state.vault)
    for row in sessions:
        try:
            row["vendor_label"] = get_vendor(row["vendor"]).label
        except UnknownVendor:
            row["vendor_label"] = row["vendor"]
    return _render(request, "sessions.html", sessions=sessions)


@router.post("/sessions")
async def session_create(request: Request):
    if not _logged_in(request):
        return _login_redirect(request)
    form = await request.form()
    if not _csrf_ok(request, form):
        return RedirectResponse("/?error=csrf", status_code=303)
    vendor_id = str(form.get("vendor") or "cisco_ios")
    try:
        get_vendor(vendor_id)
    except UnknownVendor:
        return RedirectResponse("/?error=vendor", status_code=303)
    try:
        description = clean_description(str(form.get("description") or ""))
        session_id, _job = create_session(
            request.app.state.settings.db_path,
            request.app.state.vault,
            description,
            vendor_id,
        )
    except ConfigError:
        return RedirectResponse("/?error=description", status_code=303)
    except sqlite3.IntegrityError:
        return RedirectResponse("/?error=description", status_code=303)
    return RedirectResponse(f"/sessions/{session_id}?notice=created", status_code=303)


@router.post("/sessions/{session_id}/description")
async def session_description(request: Request, session_id: int):
    if not _logged_in(request):
        return _login_redirect(request)
    form = await request.form()
    if not _csrf_ok(request, form):
        return RedirectResponse(f"/sessions/{session_id}?error=csrf", status_code=303)
    row = get_session_row(request.app.state.settings.db_path, session_id)
    if row is None:
        return _render(request, "error.html", status_code=404, heading="Session not found", detail="")
    try:
        description = clean_description(str(form.get("description") or ""))
    except ConfigError:
        return RedirectResponse(f"/sessions/{session_id}?error=description", status_code=303)
    update_description(
        request.app.state.settings.db_path,
        request.app.state.vault,
        session_id,
        description,
    )
    return RedirectResponse(f"/sessions/{session_id}?notice=description", status_code=303)


@router.post("/sessions/{session_id}/delete")
async def session_delete(request: Request, session_id: int):
    if not _logged_in(request):
        return _login_redirect(request)
    form = await request.form()
    if not _csrf_ok(request, form):
        return RedirectResponse("/?error=csrf", status_code=303)
    delete_session(request.app.state.settings.db_path, session_id)
    return RedirectResponse("/?notice=deleted", status_code=303)


@router.get("/sessions/{session_id}")
def session_detail(request: Request, session_id: int):
    if not _logged_in(request):
        return _login_redirect(request)
    page = _session_page(request, session_id)
    if page is None:
        return _render(request, "error.html", status_code=404, heading="Session not found", detail="It may have been deleted.")
    return page


@router.post("/sessions/{session_id}/keywords")
async def session_keywords(request: Request, session_id: int):
    if not _logged_in(request):
        return _login_redirect(request)
    form = await request.form()
    if not _csrf_ok(request, form):
        return RedirectResponse(f"/sessions/{session_id}?error=csrf", status_code=303)
    row = get_session_row(request.app.state.settings.db_path, session_id)
    if row is None:
        return _render(request, "error.html", status_code=404, heading="Session not found", detail="")
    accepted, rejected = parse_keywords(str(form.get("keywords") or ""))
    if rejected:
        return RedirectResponse(f"/sessions/{session_id}?error=keywords", status_code=303)
    save_keywords(request.app.state.settings.db_path, request.app.state.vault, session_id, accepted)
    return RedirectResponse(f"/sessions/{session_id}?notice=keywords", status_code=303)


@router.post("/sessions/{session_id}/sanitize")
async def session_sanitize(request: Request, session_id: int):
    if not _logged_in(request):
        return _login_redirect(request)
    if _too_big(request):
        return RedirectResponse(f"/sessions/{session_id}?error=too_large", status_code=303)
    form = await request.form()
    if not _csrf_ok(request, form):
        return RedirectResponse(f"/sessions/{session_id}?error=csrf", status_code=303)
    try:
        text, filename = await _payload(request, form)
        config_id = sanitize_upload(
            request.app.state.settings,
            request.app.state.vault,
            session_id,
            text,
            filename=filename,
            label=safe_label(str(form.get("label") or "")),
        )
    except ConfigError as exc:
        return RedirectResponse(f"/sessions/{session_id}?error={exc.code}", status_code=303)
    return RedirectResponse(f"/sessions/{session_id}/configs/{config_id}?notice=sanitized", status_code=303)


@router.get("/sessions/{session_id}/configs/{config_id}")
def config_detail(request: Request, session_id: int, config_id: int):
    if not _logged_in(request):
        return _login_redirect(request)
    row = _show_session(
        request.app.state.vault,
        get_session_row(request.app.state.settings.db_path, session_id),
    )
    stored = get_config(request.app.state.settings.db_path, request.app.state.vault, session_id, config_id)
    if row is None or stored is None:
        return _render(request, "error.html", status_code=404, heading="Config not found", detail="")
    return _render(
        request,
        "config.html",
        session=row,
        config=stored,
        removed=stored["sanitized"].count("<REMOVED>"),
    )


@router.get("/sessions/{session_id}/configs/{config_id}/download")
def config_download(request: Request, session_id: int, config_id: int, which: str = "sanitized"):
    if not _logged_in(request):
        return _login_redirect(request)
    row = get_session_row(request.app.state.settings.db_path, session_id)
    stored = get_config(request.app.state.settings.db_path, request.app.state.vault, session_id, config_id)
    if row is None or stored is None:
        return Response("Not found", status_code=404)
    if which == "original":
        body = stored["original"]
        suffix = "original"
    else:
        body = stored["sanitized"]
        suffix = "sanitized"
    filename = f"{row['job_code']}-{suffix}.cfg"
    return Response(
        body,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/sessions/{session_id}/restore")
def restore_form(request: Request, session_id: int):
    if not _logged_in(request):
        return _login_redirect(request)
    page = _restore_page(request, session_id, result=None)
    if page is None:
        return _render(request, "error.html", status_code=404, heading="Session not found", detail="")
    return page


@router.post("/sessions/{session_id}/restore")
async def restore_submit(request: Request, session_id: int):
    if not _logged_in(request):
        return _login_redirect(request)
    if _too_big(request):
        return RedirectResponse(f"/sessions/{session_id}/restore?error=too_large", status_code=303)
    form = await request.form()
    if not _csrf_ok(request, form):
        return RedirectResponse(f"/sessions/{session_id}/restore?error=csrf", status_code=303)
    compare_raw = str(form.get("compare_config_id") or "").strip()
    compare_id = int(compare_raw) if compare_raw.isdigit() else None
    try:
        text, _filename = await _payload(request, form)
        restore_id = build_restore(
            request.app.state.settings,
            request.app.state.vault,
            session_id,
            text,
            compare_id,
        )
    except ConfigError as exc:
        return RedirectResponse(f"/sessions/{session_id}/restore?error={exc.code}", status_code=303)
    return RedirectResponse(f"/sessions/{session_id}/restores/{restore_id}", status_code=303)


@router.get("/sessions/{session_id}/restores/{restore_id}")
def restore_detail(request: Request, session_id: int, restore_id: int):
    if not _logged_in(request):
        return _login_redirect(request)
    row = _show_session(
        request.app.state.vault,
        get_session_row(request.app.state.settings.db_path, session_id),
    )
    stored = get_restore(request.app.state.settings.db_path, request.app.state.vault, session_id, restore_id)
    if row is None or stored is None:
        return _render(request, "error.html", status_code=404, heading="Restore not found", detail="")
    original = None
    compare_label = ""
    compare_id = stored.get("compare_config_id")
    if compare_id:
        config = get_config(
            request.app.state.settings.db_path,
            request.app.state.vault,
            session_id,
            int(compare_id),
        )
        if config is not None:
            original = config["original"]
            compare_label = config["label"] or config["filename"]
    keywords = load_keywords(request.app.state.vault, row)
    mapper = load_mapper(request.app.state.settings.db_path, request.app.state.vault, session_id, keywords)
    issues, summary, diff_rows, diff_stats = review_restore(
        stored["edited"], stored["restored"], original, row["vendor"], mapper
    )
    configs = list_configs(request.app.state.settings.db_path, session_id)
    restores = list_restores(request.app.state.settings.db_path, session_id)
    try:
        vendor_label = get_vendor(row["vendor"]).label
    except UnknownVendor:
        vendor_label = row["vendor"]
    return _render(
        request,
        "restore.html",
        session=row,
        vendor_label=vendor_label,
        configs=configs,
        restores=restores,
        keywords=keywords,
        result={
            "id": stored["id"],
            "text": stored["restored"],
            "issues": issues,
            "summary": summary,
            "diff_rows": diff_rows,
            "diff_stats": diff_stats,
            "compare_label": compare_label,
            "has_original": original is not None,
        },
    )


@router.get("/sessions/{session_id}/restores/{restore_id}/download")
def restore_download(request: Request, session_id: int, restore_id: int):
    if not _logged_in(request):
        return _login_redirect(request)
    row = get_session_row(request.app.state.settings.db_path, session_id)
    stored = get_restore(request.app.state.settings.db_path, request.app.state.vault, session_id, restore_id)
    if row is None or stored is None:
        return Response("Not found", status_code=404)
    filename = f"{row['job_code']}-restored.cfg"
    return Response(
        stored["restored"],
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _session_page(request: Request, session_id: int):
    row = _show_session(
        request.app.state.vault,
        get_session_row(request.app.state.settings.db_path, session_id),
    )
    if row is None:
        return None
    keywords = load_keywords(request.app.state.vault, row)
    mappings = list_mapping_rows(request.app.state.settings.db_path, request.app.state.vault, session_id)
    for item in mappings:
        item["type_label"] = type_label(item["type"])
    configs = list_configs(request.app.state.settings.db_path, session_id)
    try:
        vendor_label = get_vendor(row["vendor"]).label
    except UnknownVendor:
        vendor_label = row["vendor"]
    return _render(
        request,
        "session.html",
        session=row,
        vendor_label=vendor_label,
        keywords=keywords,
        keyword_text="\n".join(keywords),
        mappings=mappings,
        configs=configs,
    )


def _restore_page(request: Request, session_id: int, result):
    row = _show_session(
        request.app.state.vault,
        get_session_row(request.app.state.settings.db_path, session_id),
    )
    if row is None:
        return None
    keywords = load_keywords(request.app.state.vault, row)
    configs = list_configs(request.app.state.settings.db_path, session_id)
    restores = list_restores(request.app.state.settings.db_path, session_id)
    try:
        vendor_label = get_vendor(row["vendor"]).label
    except UnknownVendor:
        vendor_label = row["vendor"]
    return _render(
        request,
        "restore.html",
        session=row,
        vendor_label=vendor_label,
        configs=configs,
        restores=restores,
        keywords=keywords,
        result=result,
    )
