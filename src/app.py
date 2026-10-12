"""minimal flask api used as the target for the devsecops pipeline."""
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

# read config from the environment, never hardcode secrets
API_TOKEN = os.environ.get("API_TOKEN", "")


@app.get("/health")
def health():
    """liveness probe used by ci and container orchestrators."""
    return jsonify(status="ok"), 200


@app.post("/echo")
def echo():
    """echo back a json payload after basic validation."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "message" not in data:
        return jsonify(error="expected json body with a 'message' field"), 400

    message = str(data["message"])[:280]  # cap length to avoid abuse
    return jsonify(message=message), 200


@app.get("/whoami")
def whoami():
    """require a bearer token; demonstrates env-based auth."""
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    if not API_TOKEN or token != API_TOKEN:
        return jsonify(error="unauthorized"), 401
    return jsonify(user="authenticated"), 200


if __name__ == "__main__":
    # bind to localhost by default; host is overridable for containers
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    app.run(host=host, port=port)
