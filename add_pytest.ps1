# add_pytest.ps1 - adds the pytest suite to an HMS project. Run from the project root (folder containing backend\).
$ErrorActionPreference='Stop'
if (-not (Test-Path 'backend\app')) { Write-Error 'Run this from the HMS project root (backend\app not found).'; exit 1 }
New-Item -ItemType Directory -Force backend\tests | Out-Null
New-Item -ItemType File -Force backend\tests\__init__.py | Out-Null
@'
"""Test fixtures: SQLite DB, client, role-based auth helpers."""
import os
import sys
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./test_hms.db"
os.environ["SECRET_KEY"] = "test-secret-key-that-is-at-least-32-bytes-long"
os.environ["UPLOAD_DIR"] = "./test_uploads"
os.environ["AZURE_OPENAI_API_KEY"] = ""
os.environ["AZURE_OPENAI_ENDPOINT"] = ""
os.environ["AZURE_OPENAI_DEPLOYMENT"] = ""
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.security import hash_password  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Department, Doctor, Patient, Role, User  # noqa: E402

PW = "Passw0rd!"

from passlib.context import CryptContext  # noqa: E402

import app.core.security as _sec  # noqa: E402

_sec._pwd = CryptContext(schemes=["bcrypt"], bcrypt__rounds=4)


@pytest.fixture()
def db():
    """Fresh schema per test."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    from app.routers import auth as _auth

    _auth._attempts.clear()
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def client(db):
    """HTTP client."""
    with TestClient(app) as c:
        yield c


def _mk(db, role, email, name=None):
    u = User(name=name or role.value, email=email, password_hash=hash_password(PW), role=role)
    db.add(u)
    db.commit()
    return u


@pytest.fixture()
def world(db):
    """One user of each role + dept, doctor, patient profile."""
    d = {r.value: _mk(db, r, f"{r.value}@t.io") for r in Role}
    dep = Department(name="Cardio")
    db.add(dep)
    db.commit()
    doc = Doctor(user_id=d["doctor"].user_id, department_id=dep.department_id,
                 availability={k: "9-12" for k in ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")})
    pat = Patient(user_id=d["patient"].user_id, gender="Male", dob="1990-01-01")
    import datetime
    pat.dob = datetime.date(1990, 1, 1)
    db.add_all([doc, pat])
    db.commit()
    return {"users": d, "dept": dep, "doctor": doc, "patient": pat}


@pytest.fixture()
def auth(client):
    """Return headers for a role."""
    def _h(role: str):
        r = client.post("/api/v1/auth/login", json={"email": f"{role}@t.io", "password": PW})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}
    return _h
'@ | Set-Content -Encoding utf8 backend\\tests\\conftest.py
@'
"""Auth, users, departments, doctors, patients, chatbot."""
import pytest

from tests.conftest import PW

API = "/api/v1"


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_register_login_me(client):
    r = client.post(f"{API}/auth/register", json={"name": "Neo", "email": "neo@t.io", "password": PW})
    assert r.status_code == 201
    assert client.post(f"{API}/auth/register", json={"name": "Neo", "email": "neo@t.io", "password": PW}).status_code == 409
    t = client.post(f"{API}/auth/login", json={"email": "neo@t.io", "password": PW}).json()["access_token"]
    me = client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {t}"})
    assert me.json()["role"] == "patient"


def test_login_bad_and_422(client, world):
    assert client.post(f"{API}/auth/login", json={"email": "admin@t.io", "password": "nope"}).status_code == 401
    assert client.post(f"{API}/auth/register", json={"name": "x", "email": "bad", "password": "short"}).status_code == 422


def test_no_token_401(client):
    assert client.get(f"{API}/users").status_code == 401


@pytest.mark.parametrize("role,code", [("admin", 200), ("super_admin", 200), ("doctor", 403), ("patient", 403),
                                       ("receptionist", 403), ("pharmacist", 403), ("lab_technician", 403)])
def test_users_rbac(client, world, auth, role, code):
    assert client.get(f"{API}/users", headers=auth(role)).status_code == code


def test_user_crud(client, world, auth):
    h = auth("admin")
    r = client.post(f"{API}/users", headers=h, json={"name": "Pat", "email": "p@t.io", "password": PW, "role": "pharmacist"})
    assert r.status_code == 201
    uid = r.json()["user_id"]
    assert client.put(f"{API}/users/{uid}", headers=h, json={"name": "Pat2"}).json()["name"] == "Pat2"
    assert client.delete(f"{API}/users/{uid}", headers=h).status_code == 204
    assert client.put(f"{API}/users/00000000-0000-0000-0000-000000000000", headers=h, json={}).status_code == 404


def test_departments(client, world, auth):
    h = auth("admin")
    assert client.post(f"{API}/departments", headers=h, json={"name": "Neuro"}).status_code == 201
    assert client.post(f"{API}/departments", headers=h, json={"name": "Neuro"}).status_code == 409
    assert client.post(f"{API}/departments", headers=auth("doctor"), json={"name": "X1"}).status_code == 403
    assert len(client.get(f"{API}/departments", headers=auth("patient")).json()) == 2
    did = str(world["dept"].department_id)
    assert client.delete(f"{API}/departments/{did}", headers=h).status_code == 409


def test_doctors(client, world, auth):
    h = auth("admin")
    body = {"name": "Dr X", "email": "dx@t.io", "password": PW, "department_id": str(world["dept"].department_id),
            "availability": {"Mon": "10-2"}}
    assert client.post(f"{API}/doctors", headers=h, json=body).status_code == 201
    assert client.post(f"{API}/doctors", headers=auth("patient"), json=body).status_code == 403
    did = str(world["doctor"].doctor_id)
    r = client.get(f"{API}/doctors/{did}/availability?day=2026-10-12T00:00:00", headers=auth("patient"))
    assert r.status_code == 200 and len(r.json()["free_slots"]) == 3


def test_patients_scope(client, world, auth):
    r = client.get(f"{API}/patients", headers=auth("patient"))
    assert len(r.json()) == 1
    pid = str(world["patient"].patient_id)
    assert client.get(f"{API}/patients/{pid}", headers=auth("patient")).status_code == 200
    assert client.get(f"{API}/patients", headers=auth("receptionist")).status_code == 200
    assert client.get(f"{API}/patients", headers=auth("lab_technician")).status_code == 200
    new = {"name": "Walk In", "email": "w@t.io", "password": PW, "gender": "Female", "dob": "2000-02-02"}
    assert client.post(f"{API}/patients", headers=auth("receptionist"), json=new).status_code == 201
    assert client.post(f"{API}/patients", headers=auth("patient"), json=new).status_code == 403
    other = client.get(f"{API}/patients", headers=auth("receptionist")).json()
    oid = next(p["patient_id"] for p in other if p["email"] == "w@t.io")
    assert client.get(f"{API}/patients/{oid}", headers=auth("patient")).status_code == 403
    assert client.get(f"{API}/patients/00000000-0000-0000-0000-000000000000", headers=auth("admin")).status_code == 404


def test_chat_offline(client, world, auth):
    r = client.post(f"{API}/chat", headers=auth("patient"), json={"message": "how do I book an appointment?"})
    assert r.status_code == 200 and r.json()["source"] == "offline" and "Appointments" in r.json()["reply"]
    med = client.post(f"{API}/chat", headers=auth("patient"), json={"message": "what dose should I take?"})
    assert "consult your doctor" in med.json()["reply"].lower()
    assert client.post(f"{API}/chat", json={"message": "hi"}).status_code == 401
    assert client.get(f"{API}/chat/status", headers=auth("patient")).json() == {"azure_configured": False}


def test_chat_azure_mock(client, world, auth, monkeypatch):
    import httpx

    from app.core import config

    monkeypatch.setattr(config.get_settings(), "azure_openai_endpoint", "https://x.openai.azure.com")
    monkeypatch.setattr(config.get_settings(), "azure_openai_api_key", "k")
    monkeypatch.setattr(config.get_settings(), "azure_openai_deployment", "gpt")

    class R:
        def raise_for_status(self): ...
        def json(self): return {"choices": [{"message": {"content": " Hello from Azure "}}]}

    seen = {}
    def fake(url, headers, timeout, json):
        seen.update(url=url, key=headers["api-key"], n=len(json["messages"]))
        return R()
    monkeypatch.setattr(httpx, "post", fake)
    r = client.post(f"{API}/chat", headers=auth("doctor"), json={"message": "hi", "history": []})
    assert r.json() == {"reply": "Hello from Azure", "source": "azure"}
    assert "/openai/deployments/gpt/chat/completions" in seen["url"] and seen["key"] == "k"
    monkeypatch.setattr(httpx, "post", lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("x")))
    assert client.post(f"{API}/chat", headers=auth("doctor"), json={"message": "hi"}).json()["source"] == "offline"
'@ | Set-Content -Encoding utf8 backend\\tests\\test_core.py
@'
"""Appointments, prescriptions, lab, billing, pharmacy, reports + integration flow."""
from datetime import date, timedelta

import pytest

from tests.conftest import PW

API = "/api/v1"


def _next_weekday_dt(hour=9):
    d = date.today() + timedelta(days=1)
    return f"{d.isoformat()}T{hour:02d}:00:00"


def _book(client, world, auth, hour=9, role="patient"):
    body = {"doctor_id": str(world["doctor"].doctor_id), "appointment_date": _next_weekday_dt(hour)}
    if role == "receptionist":
        body["patient_id"] = str(world["patient"].patient_id)
    return client.post(f"{API}/appointments", headers=auth(role), json=body)


def test_booking_rules(client, world, auth):
    r = _book(client, world, auth)
    assert r.status_code == 201
    assert _book(client, world, auth, role="receptionist").status_code == 409
    assert _book(client, world, auth, hour=20).status_code == 422
    assert client.post(f"{API}/appointments", headers=auth("pharmacist"), json={}).status_code == 403
    aid = r.json()["appointment_id"]
    assert client.patch(f"{API}/appointments/{aid}/cancel", headers=auth("patient")).json()["status"] == "Cancelled"
    assert _book(client, world, auth, role="receptionist").status_code == 201
    assert client.get(f"{API}/notifications", headers=auth("doctor")).json()


def test_appointment_scoping(client, world, auth):
    _book(client, world, auth)
    assert len(client.get(f"{API}/appointments", headers=auth("doctor")).json()) == 1
    assert len(client.get(f"{API}/appointments", headers=auth("patient")).json()) == 1
    assert client.get(f"{API}/appointments", headers=auth("lab_technician")).status_code == 403
    aid = client.get(f"{API}/appointments", headers=auth("doctor")).json()[0]["appointment_id"]
    assert client.put(f"{API}/appointments/{aid}", headers=auth("patient"), json={"status": "Completed"}).status_code == 403
    assert client.put(f"{API}/appointments/{aid}", headers=auth("doctor"), json={"status": "Completed"}).status_code == 200
    assert client.patch(f"{API}/appointments/00000000-0000-0000-0000-000000000000/cancel", headers=auth("doctor")).status_code == 404


def _full_flow(client, world, auth):
    aid = _book(client, world, auth).json()["appointment_id"]
    rx = client.post(f"{API}/prescriptions", headers=auth("doctor"),
                     json={"appointment_id": aid, "diagnosis": "Flu", "medicines": [{"name": "Paracetamol", "dosage": "1-0-1"}]})
    assert rx.status_code == 201
    return aid, rx.json()["prescription_id"]


def test_prescriptions(client, world, auth):
    aid, rid = _full_flow(client, world, auth)
    assert client.get(f"{API}/appointments", headers=auth("doctor")).json()[0]["status"] == "Completed"
    assert client.get(f"{API}/prescriptions/{rid}", headers=auth("patient")).status_code == 200
    assert client.get(f"{API}/prescriptions/{rid}", headers=auth("pharmacist")).status_code == 200
    assert client.get(f"{API}/prescriptions/{rid}", headers=auth("receptionist")).status_code == 403
    assert client.post(f"{API}/prescriptions", headers=auth("patient"), json={}).status_code == 403
    assert client.post(f"{API}/prescriptions", headers=auth("doctor"), json={"appointment_id": aid}).status_code == 422
    pid = str(world["patient"].patient_id)
    assert len(client.get(f"{API}/patients/{pid}/prescriptions", headers=auth("patient")).json()) == 1


def test_lab(client, world, auth):
    pid = str(world["patient"].patient_id)
    f = {"file": ("r.pdf", b"%PDF-1.4 x", "application/pdf")}
    r = client.post(f"{API}/lab-reports", headers=auth("lab_technician"), data={"patient_id": pid, "test_name": "CBC"}, files=f)
    assert r.status_code == 201
    rid = r.json()["report_id"]
    bad = client.post(f"{API}/lab-reports", headers=auth("lab_technician"), data={"patient_id": pid, "test_name": "X"},
                      files={"file": ("m.exe", b"x", "application/octet-stream")})
    assert bad.status_code == 422
    assert client.post(f"{API}/lab-reports", headers=auth("doctor"), data={"patient_id": pid, "test_name": "X"}).status_code == 403
    assert len(client.get(f"{API}/lab-reports", headers=auth("patient")).json()) == 1
    assert client.get(f"{API}/lab-reports/{rid}/download", headers=auth("patient")).content.startswith(b"%PDF")
    assert client.get(f"{API}/lab-reports/{rid}/download", headers=auth("pharmacist")).status_code == 403


def test_billing_flow(client, world, auth):
    pid = str(world["patient"].patient_id)
    body = {"patient_id": pid, "services": [{"name": "Consult", "amount": "500"}, {"name": "CBC", "amount": "250.50"}]}
    r = client.post(f"{API}/billing", headers=auth("receptionist"), json=body)
    assert r.status_code == 201 and float(r.json()["total_amount"]) == 750.50
    bid = r.json()["bill_id"]
    assert client.post(f"{API}/billing", headers=auth("patient"), json=body).status_code == 403
    assert client.post(f"{API}/billing", headers=auth("receptionist"), json={"patient_id": pid, "services": []}).status_code == 422
    p = client.patch(f"{API}/billing/{bid}/payment", headers=auth("receptionist"), json={"payment_status": "Paid", "payment_mode": "Card"})
    assert p.json()["payment_status"] == "Paid"
    pdf = client.get(f"{API}/billing/{bid}/invoice.pdf", headers=auth("patient"))
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert client.get(f"{API}/billing/{bid}", headers=auth("doctor")).status_code == 403
    assert len(client.get(f"{API}/billing", headers=auth("patient")).json()) == 1


@pytest.mark.parametrize("role,code", [("pharmacist", 200), ("admin", 200), ("patient", 403), ("doctor", 403)])
def test_pharmacy_rbac(client, world, auth, role, code):
    assert client.get(f"{API}/medicines", headers=auth(role)).status_code == code


def test_pharmacy_dispense(client, world, auth):
    h = auth("pharmacist")
    m = {"name": "Paracetamol", "quantity_available": 5, "expiry_date": (date.today() + timedelta(days=10)).isoformat(), "unit_price": "2"}
    assert client.post(f"{API}/medicines", headers=h, json=m).status_code == 201
    assert client.post(f"{API}/medicines", headers=h, json=m).status_code == 409
    _, rid = _full_flow(client, world, auth)
    ok = client.post(f"{API}/pharmacy/dispense", headers=h, json={"prescription_id": rid, "items": [{"name": "Paracetamol", "quantity": 2}]})
    assert ok.json()["dispensed"][0]["remaining"] == 3
    assert client.post(f"{API}/pharmacy/dispense", headers=h, json={"prescription_id": rid, "items": [{"name": "Paracetamol", "quantity": 9}]}).status_code == 409
    assert client.post(f"{API}/pharmacy/dispense", headers=h, json={"prescription_id": rid, "items": [{"name": "Aspirin", "quantity": 1}]}).status_code == 422
    a = client.get(f"{API}/medicines/alerts", headers=h).json()
    assert len(a["low_stock"]) == 1 and len(a["near_expiry"]) == 1


@pytest.mark.parametrize("role,code", [("admin", 200), ("super_admin", 200), ("doctor", 403), ("receptionist", 403)])
def test_reports_rbac(client, world, auth, role, code):
    assert client.get(f"{API}/reports/revenue", headers=auth(role)).status_code == code


def test_reports_and_export(client, world, auth):
    pid = str(world["patient"].patient_id)
    b = client.post(f"{API}/billing", headers=auth("receptionist"), json={"patient_id": pid, "services": [{"name": "C", "amount": "100"}]}).json()
    client.patch(f"{API}/billing/{b['bill_id']}/payment", headers=auth("receptionist"), json={"payment_status": "Paid"})
    _full_flow(client, world, auth)
    h = auth("admin")
    assert client.get(f"{API}/reports/revenue", headers=h).json()[0]["revenue"] == 100.0
    assert client.get(f"{API}/reports/patients-seen", headers=h).json()[0]["patients"] == 1
    assert client.get(f"{API}/reports/top-departments", headers=h).json()[0]["department"] == "Cardio"
    assert b"revenue" in client.get(f"{API}/reports/export?format=csv", headers=h).content
    assert client.get(f"{API}/reports/export?format=pdf&report=top-departments", headers=h).content.startswith(b"%PDF")
    assert client.get(f"{API}/reports/export?format=xml", headers=h).status_code == 422


def test_audit_written(client, world, auth, db):
    from app.models import AuditLog

    _book(client, world, auth)
    actions = {a.action for a in db.query(AuditLog).all()}
    assert {"LOGIN", "CREATE"} <= actions


def test_seed_super_admin(db, monkeypatch):
    from app.core import config
    from app.models import Role, User
    from app.services.seed import seed_demo, seed_super_admin

    monkeypatch.setattr(config.get_settings(), "admin_email", "Root@T.io")
    monkeypatch.setattr(config.get_settings(), "admin_password", PW)
    seed_super_admin(db)
    assert db.query(User).filter(User.role == Role.super_admin).count() == 1
    seed_demo(db)
    seed_demo(db)
    assert db.query(User).filter(User.email == "doctor@hms-demo.com").count() == 1
'@ | Set-Content -Encoding utf8 backend\\tests\\test_workflow.py
@'
[pytest]
testpaths = tests
addopts = -q --cov=app --cov-report=term-missing --cov-fail-under=80
filterwarnings =
    ignore::DeprecationWarning
    ignore::jwt.warnings.InsecureKeyLengthWarning
'@ | Set-Content -Encoding utf8 backend\\pytest.ini
@'
pytest>=8.0
pytest-cov>=5.0
httpx>=0.27
'@ | Set-Content -Encoding utf8 backend\\requirements-test.txt
Set-Location backend
python -m pip install -q -r requirements-test.txt
python -m pytest
