import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import app, Base, get_db

# ── In-memory SQLite database for tests ──────────────────────────────────────
# StaticPool ensures every SQLAlchemy connection reuses the same underlying
# sqlite3 connection, so the tables created in setup are visible in requests.

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_database():
    """Create tables before each test and drop them after."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(setup_database):
    """Return a TestClient backed by the test database."""

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ── Registration tests ────────────────────────────────────────────────────────


def test_register_user(client):
    response = client.post(
        "/register",
        json={"username": "alice", "email": "alice@example.com", "password": "secret"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "alice"
    assert data["email"] == "alice@example.com"
    assert data["is_active"] is True
    assert "id" in data
    assert "password" not in data


def test_register_duplicate_username(client):
    client.post(
        "/register",
        json={"username": "bob", "email": "bob@example.com", "password": "pass"},
    )
    response = client.post(
        "/register",
        json={"username": "bob", "email": "other@example.com", "password": "pass"},
    )
    assert response.status_code == 400
    assert "Username already registered" in response.json()["detail"]


def test_register_duplicate_email(client):
    client.post(
        "/register",
        json={"username": "carol", "email": "shared@example.com", "password": "pass"},
    )
    response = client.post(
        "/register",
        json={"username": "dave", "email": "shared@example.com", "password": "pass"},
    )
    assert response.status_code == 400
    assert "Email already registered" in response.json()["detail"]


# ── Login tests ───────────────────────────────────────────────────────────────


def test_login_success(client):
    client.post(
        "/register",
        json={"username": "eve", "email": "eve@example.com", "password": "mypass"},
    )
    response = client.post("/login", data={"username": "eve", "password": "mypass"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password(client):
    client.post(
        "/register",
        json={"username": "frank", "email": "frank@example.com", "password": "correct"},
    )
    response = client.post(
        "/login", data={"username": "frank", "password": "wrong"}
    )
    assert response.status_code == 401


def test_login_nonexistent_user(client):
    response = client.post(
        "/login", data={"username": "ghost", "password": "nopass"}
    )
    assert response.status_code == 401


# ── Protected route tests ─────────────────────────────────────────────────────


def test_protected_route_with_valid_token(client):
    client.post(
        "/register",
        json={"username": "grace", "email": "grace@example.com", "password": "pwd"},
    )
    token = client.post(
        "/login", data={"username": "grace", "password": "pwd"}
    ).json()["access_token"]
    auth_header = "Bearer " + token
    response = client.get("/users/me", headers={"Authorization": auth_header})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "grace"
    assert data["email"] == "grace@example.com"


def test_protected_route_without_token(client):
    response = client.get("/users/me")
    assert response.status_code == 401


def test_protected_route_with_invalid_token(client):
    bad_header = "Bearer " + "not.a.valid.token"
    response = client.get(
        "/users/me", headers={"Authorization": bad_header}
    )
    assert response.status_code == 401
