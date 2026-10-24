"""Production refuses to boot on a placeholder or weak secret.

`cp .env.example .env` is the documented first step, so every placeholder in
that file has to be caught, not just the bare "changeme" default: a missed
SECRET_KEY line would otherwise sign every JWT with a string anyone can read.
"""

import re
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.config import Settings

_ENV_EXAMPLE = Path(__file__).resolve().parents[2] / ".env.example"
_STRONG = {
    "secret_key": "a" * 64,
    "encryption_key": Fernet.generate_key().decode(),
    "postgres_password": "strong-db-password",
    "meili_master_key": "strong-meili-key",
}


def _example_value(name: str) -> str:
    match = re.search(rf"^{name}=(.*)$", _ENV_EXAMPLE.read_text(), re.MULTILINE)
    assert match, f"{name} is no longer in .env.example"
    return match.group(1).strip()


@pytest.mark.parametrize("field", sorted(_STRONG))
def test_env_example_placeholders_refused_in_production(monkeypatch, field):
    monkeypatch.setenv("ENV", "production")
    values = {**_STRONG, field: _example_value(field.upper())}
    with pytest.raises(ValidationError, match=field):
        Settings(_env_file=None, **values)


def test_short_secret_key_refused_in_production(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    with pytest.raises(ValidationError, match="at least 32"):
        Settings(_env_file=None, **{**_STRONG, "secret_key": "short-but-not-a-placeholder"})


def test_strong_secrets_accepted_in_production(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    Settings(_env_file=None, **_STRONG)


def test_placeholders_only_warn_in_development(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    Settings(_env_file=None, secret_key=_example_value("SECRET_KEY"), encryption_key=_example_value("ENCRYPTION_KEY"))
