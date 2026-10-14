"""
Langsung Link - backend Flask.

Jalankan lokal :  pip install -r requirements.txt && python app.py
Produksi       :  gunicorn -w 2 -b 127.0.0.1:8000 app:app
                  (pasang di belakang Nginx/Caddy; set TRUST_PROXY=1 agar
                   pembatas laju membaca IP pengunjung yang benar)
"""
import os
import re

from flask import Flask, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

import resolver

app = Flask(__name__, static_folder="static", static_url_path="/static")
if os.environ.get("TRUST_PROXY") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.post("/api/resolve")
@limiter.limit("20 per minute; 300 per day")
def api_resolve():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url") or "").strip()
    if not url:
        return jsonify(error="Tempel link terlebih dahulu."), 400
    if len(url) > 2048:
        return jsonify(error="Link terlalu panjang."), 400
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    try:
        return jsonify(resolver.resolve(url))
    except resolver.UnsafeURL as e:
        return jsonify(error=str(e)), 400


@app.errorhandler(429)
def too_many(_):
    return jsonify(error="Terlalu banyak permintaan. Coba lagi sebentar lagi."), 429


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8000)), debug=False)
