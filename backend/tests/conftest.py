"""Test bootstrap: run against in-memory SQLite (no Postgres/Redis/Azure needed).

Env is set *before* the app package is imported so config picks it up. Real env
vars win via setdefault, so CI can still point tests at a real database.
"""

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("AUTH_DISABLED", "true")
os.environ.setdefault("FOUNDRY_ENDPOINT", "")  # force mock reviewer
