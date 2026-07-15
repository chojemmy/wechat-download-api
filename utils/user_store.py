#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2026 tmwgsicp
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file in the project root for full license text.
# SPDX-License-Identifier: AGPL-3.0-only
"""
Multi-user account store for local self-hosted deployments.

This module intentionally uses the same SQLite database as the RSS store so that
user accounts, WeChat credentials, subscriptions, categories, and cached
articles can be backed up together by copying data/rss.db.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Dict, Optional

_DEFAULT_DB = Path(__file__).parent.parent / "data" / "rss.db"
DB_PATH = Path(os.getenv("RSS_DB_PATH", str(_DEFAULT_DB)))
SESSION_COOKIE_NAME = "wdapi_session"
SESSION_TTL_SECONDS = int(os.getenv("APP_SESSION_TTL_SECONDS", str(30 * 24 * 3600)))
_PBKDF2_ITERATIONS = 260_000


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _hash_password(password: str, *, salt: Optional[str] = None) -> str:
    if not password:
        raise ValueError("password must not be empty")
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    ).hex()
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${digest}"


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        ).hex()
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def init_user_db() -> None:
    conn = _get_conn()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name  TEXT NOT NULL DEFAULT '',
                feed_token    TEXT NOT NULL DEFAULT '',
                is_active     INTEGER NOT NULL DEFAULT 1,
                created_at    INTEGER NOT NULL,
                updated_at    INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_sessions (
                token_hash INTEGER PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS user_credentials (
                user_id     INTEGER PRIMARY KEY,
                token       TEXT NOT NULL DEFAULT '',
                cookie      TEXT NOT NULL DEFAULT '',
                fakeid      TEXT NOT NULL DEFAULT '',
                nickname    TEXT NOT NULL DEFAULT '',
                expire_time INTEGER NOT NULL DEFAULT 0,
                updated_at  INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
        cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "feed_token" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN feed_token TEXT NOT NULL DEFAULT ''")
            conn.commit()
        rows = conn.execute("SELECT id FROM users WHERE feed_token='' OR feed_token IS NULL").fetchall()
        for row in rows:
            conn.execute("UPDATE users SET feed_token=? WHERE id=?", (secrets.token_urlsafe(24), row["id"]))
        if rows:
            conn.commit()
    finally:
        conn.close()


def create_user(username: str, password: str, display_name: str = "") -> Dict:
    username = username.strip()
    if not username:
        raise ValueError("username must not be empty")
    now = int(time.time())
    password_hash = _hash_password(password)
    conn = _get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, display_name, feed_token, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (username, password_hash, display_name.strip(), secrets.token_urlsafe(24), now, now),
        )
        conn.commit()
        return get_user_by_id(cur.lastrowid)
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT id, username, display_name, feed_token, is_active, created_at, updated_at "
            "FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[Dict]:
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT id, username, display_name, feed_token, is_active, created_at, updated_at "
            "FROM users WHERE username=?",
            (username.strip(),),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username=? AND is_active=1", (username.strip(),)
        ).fetchone()
        if not row or not _verify_password(password, row["password_hash"]):
            return None
        user = dict(row)
        user.pop("password_hash", None)
        return user
    finally:
        conn.close()


def _hash_session_token(token: str) -> int:
    # SQLite INTEGER is signed 64-bit. Use a stable 63-bit hash for compact PKs.
    return int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest()[:8], "big") >> 1


def create_session(user_id: int, ttl_seconds: int = SESSION_TTL_SECONDS) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (_hash_session_token(token), user_id, now, now + ttl_seconds),
        )
        conn.commit()
        return token
    finally:
        conn.close()


def get_user_by_session_token(token: str) -> Optional[Dict]:
    if not token:
        return None
    now = int(time.time())
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT u.id, u.username, u.display_name, u.feed_token, u.is_active, u.created_at, u.updated_at "
            "FROM user_sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1",
            (_hash_session_token(token), now),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def delete_session(token: str) -> bool:
    if not token:
        return False
    conn = _get_conn()
    try:
        conn.execute("DELETE FROM user_sessions WHERE token_hash=?", (_hash_session_token(token),))
        conn.commit()
        return conn.total_changes > 0
    finally:
        conn.close()


def save_user_credentials(user_id: int, token: str, cookie: str, fakeid: str, nickname: str, expire_time: int) -> bool:
    now = int(time.time())
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO user_credentials (user_id, token, cookie, fakeid, nickname, expire_time, updated_at) "
            "VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            "token=excluded.token, cookie=excluded.cookie, fakeid=excluded.fakeid, "
            "nickname=excluded.nickname, expire_time=excluded.expire_time, updated_at=excluded.updated_at",
            (user_id, token, cookie, fakeid, nickname, expire_time, now),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def get_user_credentials(user_id: int) -> Optional[Dict]:
    conn = _get_conn()
    try:
        row = conn.execute("SELECT * FROM user_credentials WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        if not data.get("token") or not data.get("cookie"):
            return None
        return data
    finally:
        conn.close()


def get_user_by_feed_token(feed_token: str) -> Optional[Dict]:
    if not feed_token:
        return None
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT id, username, display_name, feed_token, is_active, created_at, updated_at "
            "FROM users WHERE feed_token=? AND is_active=1",
            (feed_token,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def clear_user_credentials(user_id: int) -> bool:
    conn = _get_conn()
    try:
        conn.execute("DELETE FROM user_credentials WHERE user_id=?", (user_id,))
        conn.commit()
        return True
    finally:
        conn.close()


def list_users_with_credentials() -> list[Dict]:
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT u.id, u.username, u.display_name, u.feed_token, u.is_active, u.created_at, u.updated_at "
            "FROM users u JOIN user_credentials c ON c.user_id=u.id "
            "WHERE u.is_active=1 AND c.token!='' AND c.cookie!='' "
            "ORDER BY u.id"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
