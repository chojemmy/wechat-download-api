#!/usr/bin/env python3
import os
import tempfile
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient


def fresh_app():
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ['RSS_DB_PATH'] = str(Path(tmp.name) / 'rss.db')
    os.environ['APP_BOOTSTRAP_USERNAME'] = 'legacy-admin'
    os.environ['APP_BOOTSTRAP_PASSWORD'] = 'legacy-password-123'

    from utils import rss_store, user_store
    user_store.init_user_db()
    rss_store.init_db()
    from app import app
    return app, tmp


def test_multi_user_isolation():
    app, tmp = fresh_app()
    try:
        c1, c2 = TestClient(app), TestClient(app)
        r = c1.post('/api/users/register', json={'username':'alice','password':'password123'})
        assert r.status_code == 200, r.text
        r = c2.post('/api/users/register', json={'username':'bob','password':'password123'})
        assert r.status_code == 200, r.text

        assert c1.post('/api/rss/subscribe', json={'fakeid':'fid-a','nickname':'A'}).status_code == 200
        assert c2.post('/api/rss/subscribe', json={'fakeid':'fid-b','nickname':'B'}).status_code == 200

        d1 = c1.get('/api/rss/subscriptions').json()['data']
        d2 = c2.get('/api/rss/subscriptions').json()['data']
        assert [x['fakeid'] for x in d1] == ['fid-a']
        assert [x['fakeid'] for x in d2] == ['fid-b']
        assert 'feed_token=' in d1[0]['rss_url']
        assert 'feed_token=' in d2[0]['rss_url']
        assert c1.get('/api/rss/all').status_code == 401
        assert c1.get(d1[0]['rss_url'].replace('http://testserver', '')).status_code == 200
    finally:
        tmp.cleanup()


def test_protected_without_login():
    app, tmp = fresh_app()
    try:
        c = TestClient(app)
        r = c.get('/api/rss/subscriptions')
        assert r.status_code == 401
        assert r.headers.get('X-Login-Url') == '/user-login.html'
    finally:
        tmp.cleanup()


if __name__ == '__main__':
    test_multi_user_isolation()
    test_protected_without_login()
    print('multi-user smoke tests passed')
