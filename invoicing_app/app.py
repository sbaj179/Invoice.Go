from __future__ import annotations

import atexit
import ast
import os
import smtplib
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from jinja2 import TemplateNotFound
from postgrest.exceptions import APIError
from supabase import create_client
from zoneinfo import ZoneInfo

load_dotenv()

# -----------------------------------------------------------------------------
# Timezones
# -----------------------------------------------------------------------------
SA_TZ = ZoneInfo("Africa/Johannesburg")
UTC_TZ = ZoneInfo("UTC")

# -----------------------------------------------------------------------------
# Flask config
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me")

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
AUTH_DEBUG = os.environ.get("AUTH_DEBUG", "0").strip() == "1"

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise RuntimeError("Missing SUPABASE_URL / SUPABASE_ANON_KEY in environment/.env")

# NOTE: Service role is required for background email sending (/cron/tick, process_outbox, reminders)
if not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Missing SUPABASE_SERVICE_ROLE_KEY in environment/.env")


# -----------------------------------------------------------------------------
# PostgREST error parsing helpers
# -----------------------------------------------------------------------------
def _api_error_payload(e: Exception) -> Dict[str, Any]:
    """
    postgrest.exceptions.APIError often stores a dict payload in args[0],
    but sometimes it arrives as a string that looks like a dict.
    """
    try:
        if isinstance(e, APIError) and e.args:
            a = e.args[0]
            if isinstance(a, dict):
                return a
            if isinstance(a, str):
                try:
                    v = ast.literal_eval(a)
                    if isinstance(v, dict):
                        return v
                except Exception:
                    pass

        s = str(e)
        try:
            v = ast.literal_eval(s)
            if isinstance(v, dict):
                return v
        except Exception:
            pass

        return {"message": s}
    except Exception:
        return {"message": str(e)}


def _log_api_error(context: str, e: Exception) -> None:
    p = _api_error_payload(e)
    print(f"[API ERROR] {context}: {p} | raw={repr(e)}")


def _is_unique_customer_email_violation(payload: Dict[str, Any]) -> bool:
    code = str(payload.get("code") or "")
    msg = (payload.get("message") or "")
    return code == "23505" and "customers_org_id_email_key" in msg


def _is_fk_violation(payload: Dict[str, Any]) -> bool:
    code = str(payload.get("code") or "")
    msg = (payload.get("message") or "").lower()
    return code == "23503" or "foreign key" in msg


# -----------------------------------------------------------------------------
# Auth error helpers
# -----------------------------------------------------------------------------
def _extract_auth_error(e: Exception) -> Tuple[str, Optional[str], Optional[int]]:
    msg = str(e)
    code = getattr(e, "code", None)
    status = getattr(e, "status", None)

    if hasattr(e, "message") and isinstance(getattr(e, "message"), str):
        msg = getattr(e, "message")

    if hasattr(e, "args") and e.args:
        for a in e.args:
            if isinstance(a, dict):
                msg = a.get("message") or msg
                code = a.get("code") or code
                status = a.get("status") or status

    return msg, code, status


def _flash_auth_failure(prefix: str, e: Exception) -> None:
    msg, code, status = _extract_auth_error(e)
    print(f"{prefix} ERROR:", {"message": msg, "code": code, "status": status, "raw": repr(e)})

    combined = (msg or "").lower()
    if code == "email_not_confirmed" or "email not confirmed" in combined or "confirm" in combined:
        flash("Email not confirmed. Disable confirmation for dev or confirm the user in Supabase.", "danger")
        return

    flash(f"{prefix} failed: {msg}" if AUTH_DEBUG else f"{prefix} failed.", "danger")


# -----------------------------------------------------------------------------
# Supabase clients
# -----------------------------------------------------------------------------
def sb_admin():
    # Service role bypasses RLS (ONLY for automation/background)
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


def sb_user_from_session():
    """
    User client carries JWT so RLS enforces tenant isolation.
    Tries refresh if session expired.
    """
    access = session.get("sb_access_token")
    refresh = session.get("sb_refresh_token")
    if not access or not refresh:
        raise PermissionError("Not authenticated")

    client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

    try:
        client.auth.set_session(access, refresh)
        return client
    except Exception as e:
        # try refresh
        try:
            refreshed = None
            if hasattr(client.auth, "refresh_session"):
                refreshed = client.auth.refresh_session(refresh)
            elif hasattr(client.auth, "refresh"):
                refreshed = client.auth.refresh(refresh)

            new_session = getattr(refreshed, "session", None) or refreshed
            if new_session and getattr(new_session, "access_token", None) and getattr(new_session, "refresh_token", None):
                session["sb_access_token"] = new_session.access_token
                session["sb_refresh_token"] = new_session.refresh_token
                client.auth.set_session(new_session.access_token, new_session.refresh_token)
                return client
        except Exception:
            pass
        raise e


def safe_user_client_or_logout():
    try:
        return sb_user_from_session()
    except Exception:
        session.clear()
        raise PermissionError("Session invalid")


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            _ = safe_user_client_or_logout()
        except PermissionError:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


# -----------------------------------------------------------------------------
# Time helpers
# -----------------------------------------------------------------------------
def _to_date(v) -> Optional[date]:
    if v is None:
        return None
    if isinstance(v, date) and not isinstance(v, datetime):
        return v
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).date()
        except Exception:
            try:
                return datetime.strptime(v, "%Y-%m-%d").date()
            except Exception:
                return None
    return None


def dtlocal_to_utc_iso(dtlocal: str) -> str:
    # "YYYY-MM-DDTHH:MM" in SA time -> UTC ISO string
    d = datetime.strptime(dtlocal, "%Y-%m-%dT%H:%M")
    local = d.replace(tzinfo=SA_TZ)
    return local.astimezone(UTC_TZ).isoformat()


def utc_iso_to_sa_display(iso: str) -> str:
    if not iso:
        return ""
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC_TZ)
    return dt.astimezone(SA_TZ).strftime("%Y-%m-%d %H:%M")


def utc_now_iso() -> str:
    return datetime.now(tz=UTC_TZ).isoformat()


# -----------------------------------------------------------------------------
# Org helpers
# -----------------------------------------------------------------------------
def ensure_active_org(client) -> None:
    if session.get("active_org_id"):
        return

    user_id = client.auth.get_user().user.id
    res = (
        client.table("org_memberships")
        .select("org_id, role, status, created_at")
        .eq("user_id", user_id)
        .eq("status", "active")
        .order("created_at", desc=False)
        .execute()
    )
    rows = res.data or []
    if not rows:
        raise RuntimeError("No active organization membership found for this user")

    session["active_org_id"] = rows[0]["org_id"]
    session["active_org_role"] = rows[0]["role"]


def active_org_id() -> str:
    oid = session.get("active_org_id")
    if not oid:
        raise RuntimeError("Active org not set")
    return oid


def active_user_id(client) -> str:
    return client.auth.get_user().user.id


# -----------------------------------------------------------------------------
# SMTP (Brevo) – supports plain + HTML
# -----------------------------------------------------------------------------
def send_email_smtp(to_email: str, subject: str, body_text: str, body_html: Optional[str] = None) -> None:
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")
    from_name = os.environ.get("SMTP_FROM_NAME", "Invoicing")
    from_email = os.environ.get("SMTP_FROM_EMAIL")

    if not host or not user or not password or not from_email:
        raise RuntimeError("Missing SMTP env vars (SMTP_HOST/PORT/USER/PASS/FROM_EMAIL)")

    msg = EmailMessage()
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    with smtplib.SMTP(host, port, timeout=25) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        smtp.login(user, password)
        smtp.send_message(msg)


# -----------------------------------------------------------------------------
# Email building (render invoice template at SEND TIME)
# -----------------------------------------------------------------------------
def _fallback_invoice_html(payload: Dict[str, Any]) -> str:
    items_html = "".join(
        f"<tr><td>{it['description']}</td><td align='right'>{it['quantity']}</td>"
        f"<td align='right'>R{it['unit_price']:.2f}</td><td align='right'>R{it['line_total']:.2f}</td></tr>"
        for it in payload["items"]
    )
    return f"""
    <html><body style="font-family:Arial,Helvetica,sans-serif;">
      <h2>Invoice {payload['invoice_number']}</h2>
      <p>Hi <b>{payload['customer_name']}</b>,</p>
      <p>Due: <b>{payload['due_date'] or '—'}</b><br>
         Total: <b>R{payload['total']:.2f}</b></p>
      <p>{payload.get('notes','') or ''}</p>
      <table width="100%" cellpadding="6" cellspacing="0" border="1" style="border-collapse:collapse;">
        <tr><th align="left">Description</th><th align="right">Qty</th><th align="right">Unit</th><th align="right">Line</th></tr>
        {items_html}
      </table>
      <p><b>Total: R{payload['total']:.2f}</b></p>
    </body></html>
    """


def build_invoice_email(admin, invoice_id: str) -> Tuple[str, str, str, str]:
    inv = (
        admin.table("invoices")
        .select("id,invoice_number,due_date,subtotal,tax,total,notes,status,paid_at,customer_id,customers(name,email)")
        .eq("id", invoice_id)
        .single()
        .execute()
        .data
    )

    cust = inv.get("customers") or {}
    to_email = (cust.get("email") or "").strip()
    if not to_email:
        raise RuntimeError("Customer has no email address")

    items = (
        admin.table("invoice_items")
        .select("description,quantity,unit_price,line_total")
        .eq("invoice_id", invoice_id)
        .order("position")
        .execute()
        .data
        or []
    )

    subtotal = float(inv.get("subtotal") or 0)
    tax = float(inv.get("tax") or 0)
    total = float(inv.get("total") or 0)

    subject = f"Invoice {inv['invoice_number']} due {inv.get('due_date') or '—'}"

    text_lines = [
        f"Invoice: {inv['invoice_number']}",
        f"Due date: {inv.get('due_date') or '—'}",
        f"Total: R{total:.2f}",
    ]
    if inv.get("notes"):
        text_lines.append(f"Notes: {inv['notes']}")
    text_lines.append("")
    text_lines.append("Items:")
    for it in items:
        text_lines.append(
            f"- {it['description']} | qty {it['quantity']} | R{float(it['unit_price']):.2f} | line R{float(it['line_total']):.2f}"
        )
    body_text = "\n".join(text_lines)

    payload = {
        "invoice_number": inv["invoice_number"],
        "due_date": inv.get("due_date"),
        "subtotal": subtotal,
        "tax": tax,
        "total": total,
        "notes": inv.get("notes") or "",
        "customer_name": cust.get("name") or "",
        "items": [
            {
                "description": it["description"],
                "quantity": it["quantity"],
                "unit_price": float(it["unit_price"]),
                "line_total": float(it["line_total"]),
            }
            for it in items
        ],
        "sent_at": datetime.now(tz=SA_TZ).strftime("%Y-%m-%d %H:%M"),
    }

    with app.app_context():
        try:
            body_html = render_template("emails/invoice_email.html", **payload)
        except TemplateNotFound:
            body_html = _fallback_invoice_html(payload)

    return to_email, subject, body_text, body_html


def build_reminder_email(admin, invoice_id: str) -> Tuple[str, str, str, str]:
    inv = (
        admin.table("invoices")
        .select("id,invoice_number,due_date,total,status,paid_at,customers(name,email)")
        .eq("id", invoice_id)
        .single()
        .execute()
        .data
    )

    if inv.get("paid_at") is not None or inv.get("status") == "paid":
        raise RuntimeError("Invoice already paid (skip reminder)")

    cust = inv.get("customers") or {}
    to_email = (cust.get("email") or "").strip()
    if not to_email:
        raise RuntimeError("Customer has no email address")

    total = float(inv.get("total") or 0)

    subject = f"Payment reminder: {inv['invoice_number']} due {inv.get('due_date') or '—'}"
    body_text = (
        f"Hi {cust.get('name','')},\n\n"
        f"This is a reminder that invoice {inv['invoice_number']} is due on {inv.get('due_date') or '—'}.\n"
        f"Amount due: R{total:.2f}\n\n"
        f"Please make payment at your earliest convenience.\n"
    )

    body_html = f"""
    <html><body style="font-family:Arial,Helvetica,sans-serif;">
      <h3>Payment Reminder</h3>
      <p>Hi <b>{cust.get('name','')}</b>,</p>
      <p>This is a reminder that invoice <b>{inv['invoice_number']}</b> is due on <b>{inv.get('due_date') or '—'}</b>.</p>
      <p>Amount due: <b>R{total:.2f}</b></p>
      <p>Please make payment at your earliest convenience.</p>
    </body></html>
    """
    return to_email, subject, body_text, body_html


# -----------------------------------------------------------------------------
# UI shaping
# -----------------------------------------------------------------------------
def customers_with_invoice_counts(client, org_id: str) -> List[Dict[str, Any]]:
    customers = (
        client.table("customers")
        .select("id,name,email,created_at")
        .eq("org_id", org_id)
        .order("name")
        .execute()
        .data
        or []
    )

    inv_rows = client.table("invoices").select("customer_id").eq("org_id", org_id).execute().data or []
    counts: Dict[str, int] = {}
    for r in inv_rows:
        cid = r["customer_id"]
        counts[cid] = counts.get(cid, 0) + 1
    for c in customers:
        c["invoice_count"] = counts.get(c["id"], 0)
    return customers


def list_invoices_for_ui(client, org_id: str) -> List[Dict[str, Any]]:
    rows = (
        client.table("invoices")
        .select("id,invoice_number,due_date,status,total,notes,paid_at,customers(name,email)")
        .eq("org_id", org_id)
        .order("due_date")
        .execute()
        .data
        or []
    )

    shaped: List[Dict[str, Any]] = []
    ids: List[str] = []

    for r in rows:
        r["customer"] = r.get("customers") or {"name": "Unknown", "email": ""}
        r.pop("customers", None)

        dd = _to_date(r.get("due_date"))
        r["due_date"] = dd
        r["_due_date_missing"] = dd is None

        r["next_send_at"] = None
        r["next_reminder_at"] = None

        shaped.append(r)
        ids.append(r["id"])

    if not ids:
        return shaped

    outbox = (
        client.table("message_outbox")
        .select("invoice_id,kind,scheduled_for,status")
        .eq("status", "queued")
        .in_("invoice_id", ids)
        .order("scheduled_for", desc=False)
        .execute()
        .data
        or []
    )

    min_send: Dict[str, str] = {}
    min_rem: Dict[str, str] = {}

    for m in outbox:
        inv_id = m["invoice_id"]
        kind = m.get("kind")
        sched = m.get("scheduled_for")
        if not sched:
            continue
        if kind == "send_invoice" and inv_id not in min_send:
            min_send[inv_id] = utc_iso_to_sa_display(sched)
        if kind == "reminder" and inv_id not in min_rem:
            min_rem[inv_id] = utc_iso_to_sa_display(sched)

    for r in shaped:
        rid = r["id"]
        r["next_send_at"] = min_send.get(rid)
        r["next_reminder_at"] = min_rem.get(rid)

    return shaped


# -----------------------------------------------------------------------------
# Reminder automation (org-level)
# -----------------------------------------------------------------------------
def enqueue_due_reminders() -> None:
    admin = sb_admin()
    today = date.today()

    today_start = datetime(today.year, today.month, today.day, tzinfo=UTC_TZ)
    tomorrow_start = today_start + timedelta(days=1)

    settings = (
        admin.table("reminder_settings")
        .select("org_id,enabled,days_before,days_after,channels")
        .eq("enabled", True)
        .execute()
        .data
        or []
    )

    for s in settings:
        org_id = s["org_id"]
        days_before = s.get("days_before") or []
        days_after = s.get("days_after") or []
        channels = s.get("channels") or ["email"]

        invs = (
            admin.table("invoices")
            .select("id,due_date,status,paid_at,customer_id,customers(email)")
            .eq("org_id", org_id)
            .eq("status", "sent")
            .is_("paid_at", "null")
            .execute()
            .data
            or []
        )
        if not invs:
            continue

        org_row = admin.table("organizations").select("created_by").eq("id", org_id).single().execute().data
        created_by = org_row["created_by"]

        for inv in invs:
            due = _to_date(inv.get("due_date"))
            if not due:
                continue

            delta = (due - today).days
            should_send = (
                (delta in days_before)
                or (delta < 0 and (-delta) in days_after)
                or (delta == 0 and 0 in (days_before + days_after))
            )
            if not should_send:
                continue

            cust = inv.get("customers") or {}
            to_email = (cust.get("email") or "").strip()
            if not to_email:
                continue

            for ch in channels:
                existing = (
                    admin.table("message_outbox")
                    .select("id")
                    .eq("org_id", org_id)
                    .eq("invoice_id", inv["id"])
                    .eq("channel", ch)
                    .eq("kind", "reminder")
                    .gte("scheduled_for", today_start.isoformat())
                    .lt("scheduled_for", tomorrow_start.isoformat())
                    .execute()
                    .data
                    or []
                )
                if existing:
                    continue

                admin.table("message_outbox").insert(
                    {
                        "org_id": org_id,
                        "invoice_id": inv["id"],
                        "customer_id": inv["customer_id"],
                        "kind": "reminder",
                        "channel": ch,
                        "to_address": to_email,
                        "subject": "Payment reminder",
                        "body": "Reminder queued",
                        "status": "queued",
                        "scheduled_for": utc_now_iso(),
                        "attempts": 0,
                        "created_by": created_by,
                    }
                ).execute()


# -----------------------------------------------------------------------------
# Outbox sender (scheduled invoice send + reminders)
# -----------------------------------------------------------------------------
def process_outbox() -> None:
    admin = sb_admin()
    now_iso = utc_now_iso()

    msgs = (
        admin.table("message_outbox")
        .select("id,invoice_id,kind,channel,attempts")
        .eq("status", "queued")
        .lte("scheduled_for", now_iso)
        .order("created_at")
        .limit(25)
        .execute()
        .data
        or []
    )

    for m in msgs:
        msg_id = m["id"]
        invoice_id = m["invoice_id"]
        kind = (m.get("kind") or "reminder").strip()
        channel = (m.get("channel") or "").strip()

        if channel != "email":
            admin.table("message_outbox").update(
                {
                    "status": "failed",
                    "attempts": (m.get("attempts") or 0) + 1,
                    "last_error": f"Unsupported channel: {channel}",
                }
            ).eq("id", msg_id).execute()
            continue

        try:
            if kind == "send_invoice":
                to_email, subject, body_text, body_html = build_invoice_email(admin, invoice_id)
            else:
                to_email, subject, body_text, body_html = build_reminder_email(admin, invoice_id)

            send_email_smtp(to_email=to_email, subject=subject, body_text=body_text, body_html=body_html)

            admin.table("message_outbox").update({"status": "sent", "sent_at": utc_now_iso()}).eq("id", msg_id).execute()
            print(f"[OUTBOX] sent kind={kind} -> {to_email} (msg_id={msg_id})")

            if kind == "send_invoice":
                admin.table("invoices").update({"status": "sent"}).eq("id", invoice_id).execute()

        except Exception as e:
            err = str(e)

            # reminders for paid invoices should be cancelled, not failed
            if "already paid" in err.lower() or "skip reminder" in err.lower():
                admin.table("message_outbox").update({"status": "cancelled", "last_error": err[:1000]}).eq("id", msg_id).execute()
                print(f"[OUTBOX] cancelled kind={kind} msg_id={msg_id} reason={err}")
                continue

            admin.table("message_outbox").update(
                {
                    "status": "failed",
                    "attempts": (m.get("attempts") or 0) + 1,
                    "last_error": err[:1000],
                }
            ).eq("id", msg_id).execute()
            print(f"[OUTBOX] FAILED kind={kind} msg_id={msg_id} error={err}")


# -----------------------------------------------------------------------------
# Scheduler (local only - starts in __main__)
# -----------------------------------------------------------------------------
_scheduler: Optional[BackgroundScheduler] = None


def start_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(enqueue_due_reminders, IntervalTrigger(minutes=15), id="enqueue_due_reminders", replace_existing=True)
    _scheduler.add_job(process_outbox, IntervalTrigger(minutes=1), id="process_outbox", replace_existing=True)
    _scheduler.start()

    atexit.register(lambda: _scheduler.shutdown(wait=False) if _scheduler and _scheduler.running else None)


# -----------------------------------------------------------------------------
# Cron tick endpoint (for Vercel + external cron like cron-job.org)
# -----------------------------------------------------------------------------
@app.get("/cron/tick")
def cron_tick():
    auth = request.headers.get("authorization", "")
    secret = os.environ.get("CRON_SECRET", "").strip()
    if not secret or auth != f"Bearer {secret}":
        return {"ok": False, "error": "unauthorized"}, 401

    try:
        enqueue_due_reminders()
        process_outbox()
        return {"ok": True}
    except Exception as e:
        # Return 500 so cron provider can show failures
        return {"ok": False, "error": str(e)[:500]}, 500


# -----------------------------------------------------------------------------
# AUTH routes
# -----------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        session.clear()
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

        client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        try:
            auth = client.auth.sign_in_with_password({"email": email, "password": password})
        except Exception as e:
            _flash_auth_failure("Login", e)
            return redirect(url_for("login"))

        if not auth.session:
            flash("Login failed: no session returned.", "danger")
            return redirect(url_for("login"))

        session["sb_access_token"] = auth.session.access_token
        session["sb_refresh_token"] = auth.session.refresh_token
        session.pop("active_org_id", None)
        session.pop("active_org_role", None)

        user_client = sb_user_from_session()
        ensure_active_org(user_client)

        flash("Logged in.", "success")
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        session.clear()
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        full_name = (request.form.get("full_name") or "").strip()

        client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        try:
            res = client.auth.sign_up({"email": email, "password": password, "options": {"data": {"full_name": full_name}}})
        except Exception as e:
            _flash_auth_failure("Sign up", e)
            return redirect(url_for("signup"))

        if not res.session:
            flash("Account created. Log in.", "info")
            return redirect(url_for("login"))

        session["sb_access_token"] = res.session.access_token
        session["sb_refresh_token"] = res.session.refresh_token
        session.pop("active_org_id", None)
        session.pop("active_org_role", None)

        user_client = sb_user_from_session()
        ensure_active_org(user_client)

        flash("Account created.", "success")
        return redirect(url_for("index"))

    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------------------------------------------------------
# App routes
# -----------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    client = safe_user_client_or_logout()
    ensure_active_org(client)
    org_id = active_org_id()

    invoices = client.table("invoices").select("id,due_date,status,paid_at").eq("org_id", org_id).execute().data or []
    customers_count = len((client.table("customers").select("id").eq("org_id", org_id).execute().data or []))

    total_invoices = len(invoices)
    unpaid = sum(1 for i in invoices if i.get("paid_at") is None and i.get("status") == "sent")

    overdue = 0
    for i in invoices:
        if i.get("paid_at") is not None:
            continue
        if i.get("status") != "sent":
            continue
        dd = _to_date(i.get("due_date"))
        if dd and dd < date.today():
            overdue += 1

    return render_template(
        "index.html",
        total_customers=customers_count,
        total_invoices=total_invoices,
        unpaid_invoices=unpaid,
        overdue_invoices=overdue,
    )


@app.route("/customers")
@login_required
def list_customers():
    client = safe_user_client_or_logout()
    ensure_active_org(client)
    org_id = active_org_id()
    customers = customers_with_invoice_counts(client, org_id)
    return render_template("customers.html", customers=customers)


@app.route("/customers/add", methods=["GET", "POST"])
@login_required
def add_customer():
    client = safe_user_client_or_logout()
    ensure_active_org(client)
    org_id = active_org_id()
    user_id = active_user_id(client)

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()

        if not name or not email:
            flash("Name and email are required.", "danger")
            return redirect(url_for("add_customer"))

        existing = (
            client.table("customers")
            .select("id")
            .eq("org_id", org_id)
            .eq("email", email)
            .limit(1)
            .execute()
            .data
            or []
        )
        if existing:
            flash("That email already exists. I opened the existing customer.", "warning")
            return redirect(url_for("edit_customer", customer_id=existing[0]["id"]))

        try:
            client.table("customers").insert({"org_id": org_id, "name": name, "email": email, "created_by": user_id}).execute()
        except APIError as e:
            _log_api_error("create customer", e)
            p = _api_error_payload(e)
            if _is_unique_customer_email_violation(p):
                flash("A customer with that email already exists in your account.", "warning")
                return redirect(url_for("list_customers"))
            flash(f"Failed to create customer: {p}", "danger")
            return redirect(url_for("add_customer"))

        flash("Customer created.", "success")
        return redirect(url_for("list_customers"))

    return render_template("add_customer.html")


@app.route("/customers/<customer_id>/edit", methods=["GET", "POST"])
@login_required
def edit_customer(customer_id: str):
    client = safe_user_client_or_logout()
    ensure_active_org(client)

    cust = client.table("customers").select("id,name,email").eq("id", customer_id).single().execute().data

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()

        if not name or not email:
            flash("Name and email are required.", "danger")
            return redirect(url_for("edit_customer", customer_id=customer_id))

        try:
            client.table("customers").update({"name": name, "email": email}).eq("id", customer_id).execute()
        except APIError as e:
            _log_api_error("update customer", e)
            p = _api_error_payload(e)
            if _is_unique_customer_email_violation(p):
                flash("Another customer already uses that email in your account.", "warning")
                return redirect(url_for("edit_customer", customer_id=customer_id))
            flash(f"Failed to update customer: {p}", "danger")
            return redirect(url_for("edit_customer", customer_id=customer_id))

        flash("Customer updated.", "success")
        return redirect(url_for("list_customers"))

    return render_template("edit_customer.html", customer=cust)


@app.route("/customers/<customer_id>/delete", methods=["POST"])
@login_required
def delete_customer(customer_id: str):
    client = safe_user_client_or_logout()
    ensure_active_org(client)

    try:
        client.table("customers").delete().eq("id", customer_id).execute()
    except APIError as e:
        _log_api_error("delete customer", e)
        p = _api_error_payload(e)
        if _is_fk_violation(p):
            flash("Cannot delete customer: they have invoices. Delete invoices first.", "warning")
            return redirect(url_for("list_customers"))
        flash(f"Failed to delete customer: {p}", "danger")
        return redirect(url_for("list_customers"))

    flash("Customer deleted.", "warning")
    return redirect(url_for("list_customers"))


@app.route("/invoices")
@login_required
def list_invoices():
    client = safe_user_client_or_logout()
    ensure_active_org(client)
    org_id = active_org_id()

    invoices = list_invoices_for_ui(client, org_id)
    return render_template("invoices.html", invoices=invoices, current_date=date.today())


@app.route("/invoices/add", methods=["GET", "POST"])
@login_required
def add_invoice():
    client = safe_user_client_or_logout()
    ensure_active_org(client)
    org_id = active_org_id()
    user_id = active_user_id(client)

    customers = client.table("customers").select("id,name,email").eq("org_id", org_id).order("name").execute().data or []
    if not customers:
        flash("Add a customer first.", "danger")
        return redirect(url_for("add_customer"))

    if request.method == "POST":
        customer_id = request.form.get("customer_id")
        amount = request.form.get("amount")
        due_date_str = request.form.get("due_date")
        notes = (request.form.get("description") or "").strip()
        send_mode = (request.form.get("send_mode") or "now").strip()
        send_at = (request.form.get("send_at") or "").strip()

        if not customer_id or not amount or not due_date_str:
            flash("Customer, amount, and due date are required.", "danger")
            return redirect(url_for("add_invoice"))

        try:
            amount_value = float(amount)
        except ValueError:
            flash("Amount must be a number.", "danger")
            return redirect(url_for("add_invoice"))

        rpc = client.rpc(
            "create_invoice",
            {"p_org_id": org_id, "p_customer_id": customer_id, "p_due_date": due_date_str, "p_notes": notes},
        ).execute()

        invoice_id = rpc.data if isinstance(rpc.data, str) else (rpc.data[0] if rpc.data else None)
        if not invoice_id:
            flash("Failed to create invoice.", "danger")
            return redirect(url_for("add_invoice"))

        client.table("invoice_items").insert(
            {
                "org_id": org_id,
                "invoice_id": invoice_id,
                "position": 1,
                "description": notes or "Invoice",
                "quantity": 1,
                "unit_price": amount_value,
                "created_by": user_id,
            }
        ).execute()

        cust = client.table("customers").select("email").eq("id", customer_id).single().execute().data
        to_email = (cust.get("email") or "").strip()
        if not to_email:
            flash("Customer has no email. Add an email first.", "danger")
            return redirect(url_for("edit_customer", customer_id=customer_id))

        scheduled_for = utc_now_iso()
        if send_mode == "schedule":
            if not send_at:
                flash("Pick a send time, or choose Send now.", "danger")
                return redirect(url_for("add_invoice"))
            scheduled_for = dtlocal_to_utc_iso(send_at)

        client.table("message_outbox").insert(
            {
                "org_id": org_id,
                "invoice_id": invoice_id,
                "customer_id": customer_id,
                "kind": "send_invoice",
                "channel": "email",
                "to_address": to_email,
                "subject": "Invoice scheduled",
                "body": "Invoice scheduled",
                "status": "queued",
                "scheduled_for": scheduled_for,
                "attempts": 0,
                "created_by": user_id,
            }
        ).execute()

        flash("Invoice created. It will be sent automatically.", "success")
        return redirect(url_for("list_invoices"))

    return render_template("add_invoice.html", customers=customers)


@app.route("/invoices/<invoice_id>/send-now", methods=["POST"])
@login_required
def send_invoice_now(invoice_id: str):
    client = safe_user_client_or_logout()
    ensure_active_org(client)
    org_id = active_org_id()
    user_id = active_user_id(client)

    inv = client.table("invoices").select("id,customer_id").eq("id", invoice_id).single().execute().data
    cust = client.table("customers").select("email").eq("id", inv["customer_id"]).single().execute().data
    to_email = (cust.get("email") or "").strip()
    if not to_email:
        flash("Customer has no email address.", "danger")
        return redirect(url_for("list_invoices"))

    now_iso = utc_now_iso()

    existing = (
        client.table("message_outbox")
        .select("id")
        .eq("invoice_id", invoice_id)
        .eq("kind", "send_invoice")
        .eq("status", "queued")
        .order("created_at", desc=False)
        .limit(1)
        .execute()
        .data
        or []
    )

    if existing:
        client.table("message_outbox").update({"to_address": to_email, "scheduled_for": now_iso}).eq("id", existing[0]["id"]).execute()
    else:
        client.table("message_outbox").insert(
            {
                "org_id": org_id,
                "invoice_id": invoice_id,
                "customer_id": inv["customer_id"],
                "kind": "send_invoice",
                "channel": "email",
                "to_address": to_email,
                "subject": "Invoice scheduled",
                "body": "Invoice scheduled",
                "status": "queued",
                "scheduled_for": now_iso,
                "attempts": 0,
                "created_by": user_id,
            }
        ).execute()

    flash("Send queued. It will go out automatically.", "success")
    return redirect(url_for("list_invoices"))


@app.route("/invoices/<invoice_id>/edit", methods=["GET", "POST"])
@login_required
def edit_invoice(invoice_id: str):
    client = safe_user_client_or_logout()
    ensure_active_org(client)
    org_id = active_org_id()

    inv = (
        client.table("invoices")
        .select("id,invoice_number,due_date,status,total,notes,paid_at,customer_id")
        .eq("id", invoice_id)
        .single()
        .execute()
        .data
    )

    customers = client.table("customers").select("id,name,email").eq("org_id", org_id).order("name").execute().data or []

    items = (
        client.table("invoice_items")
        .select("id,unit_price,description")
        .eq("invoice_id", invoice_id)
        .order("position")
        .limit(1)
        .execute()
        .data
        or []
    )
    first_item = items[0] if items else None

    inv_for_ui = dict(inv)
    inv_for_ui["amount"] = float(first_item["unit_price"]) if first_item else float(inv.get("total") or 0)
    inv_for_ui["description"] = inv.get("notes") or (first_item["description"] if first_item else "")
    inv_for_ui["paid"] = (inv.get("status") == "paid") or (inv.get("paid_at") is not None)

    if request.method == "POST":
        customer_id = request.form.get("customer_id")
        amount = request.form.get("amount")
        due_date_str = request.form.get("due_date")
        description = (request.form.get("description") or "").strip()
        paid = (request.form.get("paid") == "on")

        if not customer_id or not amount or not due_date_str:
            flash("Customer, amount, and due date are required.", "danger")
            return redirect(url_for("edit_invoice", invoice_id=invoice_id))

        try:
            amount_value = float(amount)
        except ValueError:
            flash("Amount must be a number.", "danger")
            return redirect(url_for("edit_invoice", invoice_id=invoice_id))

        current_status = inv.get("status") or "draft"
        next_status = "paid" if paid else ("draft" if current_status == "draft" else "sent")

        update_invoice = {
            "customer_id": customer_id,
            "due_date": due_date_str,
            "notes": description,
            "status": next_status,
            "paid_at": utc_now_iso() if paid else None,
        }

        client.table("invoices").update(update_invoice).eq("id", invoice_id).execute()

        if first_item:
            client.table("invoice_items").update(
                {"description": description or "Invoice", "quantity": 1, "unit_price": amount_value}
            ).eq("id", first_item["id"]).execute()
        else:
            client.table("invoice_items").insert(
                {
                    "org_id": org_id,
                    "invoice_id": invoice_id,
                    "position": 1,
                    "description": description or "Invoice",
                    "quantity": 1,
                    "unit_price": amount_value,
                    "created_by": active_user_id(client),
                }
            ).execute()

        flash("Invoice updated.", "success")
        return redirect(url_for("list_invoices"))

    return render_template("edit_invoice.html", invoice=inv_for_ui, customers=customers)


@app.route("/invoices/<invoice_id>/delete", methods=["POST"])
@login_required
def delete_invoice(invoice_id: str):
    client = safe_user_client_or_logout()
    ensure_active_org(client)
    client.table("invoices").delete().eq("id", invoice_id).execute()
    flash("Invoice deleted.", "warning")
    return redirect(url_for("list_invoices"))


@app.route("/invoices/<invoice_id>/remind", methods=["POST"])
@login_required
def remind_invoice(invoice_id: str):
    client = safe_user_client_or_logout()
    ensure_active_org(client)
    org_id = active_org_id()
    user_id = active_user_id(client)

    inv = (
        client.table("invoices")
        .select("id,status,paid_at,customer_id,customers(email)")
        .eq("id", invoice_id)
        .single()
        .execute()
        .data
    )

    if inv.get("paid_at") is not None or inv.get("status") == "paid":
        flash("Invoice already paid.", "info")
        return redirect(url_for("list_invoices"))

    if inv.get("status") != "sent":
        flash("Invoice must be sent before reminding.", "info")
        return redirect(url_for("list_invoices"))

    cust = inv.get("customers") or {}
    to_email = (cust.get("email") or "").strip()
    if not to_email:
        flash("Customer has no email address.", "danger")
        return redirect(url_for("list_invoices"))

    client.table("message_outbox").insert(
        {
            "org_id": org_id,
            "invoice_id": inv["id"],
            "customer_id": inv["customer_id"],
            "kind": "reminder",
            "channel": "email",
            "to_address": to_email,
            "subject": "Payment reminder",
            "body": "Reminder queued",
            "status": "queued",
            "scheduled_for": utc_now_iso(),
            "attempts": 0,
            "created_by": user_id,
        }
    ).execute()

    flash("Reminder queued.", "success")
    return redirect(url_for("list_invoices"))


@app.route("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    # Local mode worker
    start_scheduler()
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)