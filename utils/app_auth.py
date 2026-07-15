#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2026 tmwgsicp
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file in the project root for full license text.
# SPDX-License-Identifier: AGPL-3.0-only
"""Application user authentication helpers."""

from __future__ import annotations

from typing import Dict

from fastapi import Cookie, HTTPException, Query, Response, status

from utils import user_store


def require_user(wdapi_session: str = Cookie(default="")) -> Dict:
    user = user_store.get_user_by_session_token(wdapi_session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="请先登录应用账号：/user-login.html",
            headers={"X-Login-Url": "/user-login.html"},
        )
    return user


def optional_user(wdapi_session: str = Cookie(default="")) -> Dict | None:
    return user_store.get_user_by_session_token(wdapi_session)


def require_feed_user(feed_token: str = Query(default="")) -> Dict:
    user = user_store.get_user_by_feed_token(feed_token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="RSS feed token 无效")
    return user


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        user_store.SESSION_COOKIE_NAME,
        token,
        max_age=user_store.SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(user_store.SESSION_COOKIE_NAME, path="/")
