
import os
import html

import click
from argon2 import PasswordHasher
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
)
from flask import Flask, jsonify, request
from flask.cli import with_appcontext
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select
from dotenv import load_dotenv

from config import Config

load_dotenv()

db = SQLAlchemy()
jwt = JWTManager()
password_hasher = PasswordHasher()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(
        db.String(80), unique=True, nullable=False
    )
    password_hash = db.Column(db.String(255), nullable=False)


class DataItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.String(2000), nullable=False)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    if not app.config.get("JWT_SECRET_KEY"):
        raise RuntimeError("JWT_SECRET_KEY is not configured")

    db.init_app(app)
    jwt.init_app(app)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    @app.post("/auth/login")
    def login():
        body = request.get_json(silent=True)

        if not isinstance(body, dict):
            return jsonify({"error": "Invalid request"}), 400

        username = body.get("username")
        password = body.get("password")

        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or not username
            or not password
            or len(username) > 80
            or len(password) > 1024
        ):
            return jsonify({"error": "Invalid credentials"}), 401

        user = db.session.scalar(
            select(User).where(User.username == username)
        )

        if user is None:
            return jsonify({"error": "Invalid credentials"}), 401

        try:
            password_hasher.verify(user.password_hash, password)
        except (VerifyMismatchError, VerificationError):
            return jsonify({"error": "Invalid credentials"}), 401

        if password_hasher.check_needs_rehash(user.password_hash):
            user.password_hash = password_hasher.hash(password)
            db.session.commit()

        token = create_access_token(identity=str(user.id))

        return jsonify({"access_token": token}), 200

    @app.get("/api/data")
    @jwt_required()
    def get_data():
        items = db.session.scalars(
            select(DataItem).order_by(DataItem.id)
        ).all()

        return jsonify([
            {
                "id": item.id,
                "title": html.escape(item.title),
                "content": html.escape(item.content),
            }
            for item in items
        ]), 200

    @app.post("/api/data")
    @jwt_required()
    def create_data():
        body = request.get_json(silent=True)

        if not isinstance(body, dict):
            return jsonify({"error": "Invalid request"}), 400

        title = body.get("title")
        content = body.get("content")

        if (
            not isinstance(title, str)
            or not isinstance(content, str)
            or not title.strip()
            or not content.strip()
            or len(title) > 200
            or len(content) > 2000
        ):
            return jsonify({"error": "Invalid input"}), 400

        item = DataItem(
            title=title.strip(),
            content=content.strip(),
            user_id=int(get_jwt_identity()),
        )

        db.session.add(item)
        db.session.commit()

        return jsonify({
            "id": item.id,
            "title": html.escape(item.title),
            "content": html.escape(item.content),
        }), 201

    @app.cli.command("init-db")
    @with_appcontext
    def init_db():
        """Create database tables."""
        db.create_all()
        click.echo("Database initialized.")

    @app.cli.command("create-user")
    @click.argument("username")
    @click.password_option()
    @with_appcontext
    def create_user(username, password):
        """Create a user with a hashed password."""
        if not username.strip() or len(username) > 80:
            raise click.ClickException("Invalid username")

        if not password or len(password) > 1024:
            raise click.ClickException("Invalid password")

        existing = db.session.scalar(
            select(User).where(User.username == username)
        )

        if existing:
            raise click.ClickException("User already exists")

        user = User(
            username=username,
            password_hash=password_hasher.hash(password),
        )
        db.session.add(user)
        db.session.commit()

        click.echo("User created successfully.")

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=False)
