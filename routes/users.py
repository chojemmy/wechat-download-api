#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2026 tmwgsicp
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file in the project root for full license text.
# SPDX-License-Identifier: AGPL-3.0-only
"""Application account routes for multi-user mode."""

from __future__ import annotations

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from utils import user_store
from utils.app_auth import clear_session_cookie, require_user, set_session_cookie

router = APIRouter()


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=80)
    password: str = Field(..., min_length=8, max_length=256)
    display_name: str = Field("", max_length=120)


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=80)
    password: str = Field(..., min_length=1, max_length=256)


@router.post("/register", summary="注册应用账号")
async def register(req: RegisterRequest, response: Response):
    try:
        user = user_store.create_user(req.username, req.password, req.display_name)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"注册失败: {e}")
    token = user_store.create_session(user["id"])
    set_session_cookie(response, token)
    return {"success": True, "user": user}


@router.post("/login", summary="登录应用账号")
async def login(req: LoginRequest, response: Response):
    user = user_store.authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    token = user_store.create_session(user["id"])
    set_session_cookie(response, token)
    return {"success": True, "user": user}


@router.post("/logout", summary="退出应用账号")
async def logout(response: Response, wdapi_session: str = Cookie(default="")):
    if wdapi_session:
        user_store.delete_session(wdapi_session)
    clear_session_cookie(response)
    return {"success": True}


@router.get("/me", summary="当前应用账号")
async def me(user=Depends(require_user)):  # type: ignore[name-defined]
    return {"success": True, "user": user}

