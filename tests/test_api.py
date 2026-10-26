
import pytest
from argon2 import PasswordHasher

from app import create_app, db, User


@pytest.fixture
def client():
    app = create_app({
        "TESTING": True,
        "JWT_SECRET_KEY": "test-only-secret-key",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })

    with app.app_context():
        db.create_all()

        user = User(
            username="student",
            password_hash=PasswordHasher().hash("test-password"),
        )
        db.session.add(user)
        db.session.commit()

        yield app.test_client()

        db.session.remove()
        db.drop_all()


def get_token(client):
    response = client.post(
        "/auth/login",
        json={
            "username": "student",
            "password": "test-password",
        },
    )
    assert response.status_code == 200
    return response.get_json()["access_token"]


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_login_success(client):
    response = client.post(
        "/auth/login",
        json={
            "username": "student",
            "password": "test-password",
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.get_json()


def test_login_wrong_password(client):
    response = client.post(
        "/auth/login",
        json={
            "username": "student",
            "password": "wrong-password",
        },
    )
    assert response.status_code == 401


def test_data_requires_token(client):
    response = client.get("/api/data")
    assert response.status_code == 401


def test_create_and_read_data(client):
    token = get_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    created = client.post(
        "/api/data",
        headers=headers,
        json={
            "title": "Test title",
            "content": "Test content",
        },
    )
    assert created.status_code == 201

    response = client.get("/api/data", headers=headers)
    assert response.status_code == 200
    assert response.get_json()[0]["title"] == "Test title"


def test_invalid_data_rejected(client):
    token = get_token(client)
    response = client.post(
        "/api/data",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "", "content": "Some content"},
    )
    assert response.status_code == 400


def test_xss_text_is_escaped(client):
    token = get_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/data",
        headers=headers,
        json={
            "title": "XSS test",
            "content": "<script>alert(1)</script>",
        },
    )

    response = client.get("/api/data", headers=headers)
    item = response.get_json()[0]

    assert "<script>" not in item["content"]
    assert "&lt;script&gt;" in item["content"]
