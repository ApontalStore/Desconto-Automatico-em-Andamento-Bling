# main.py

import threading
import time
import base64
import httpx
from flask import Flask, request

# === Configurações do App Bling (substitua pelos seus dados) ===
CLIENT_ID     = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"
REDIRECT_URI  = "https://YOUR_REPL_URL/oauth/callback"
API_URL       = "https://api.bling.com.br/Api/v3/pedidos/vendas"

# Armazenamento dos tokens em memória
token_data = {
    "access_token":  None,
    "refresh_token": None,
    "expires_at":    0
}
token_lock = threading.Lock()

app = Flask(__name__)

def get_basic_auth_header():
    """Gera o header Authorization: Basic para OAuth2."""
    creds = f"{CLIENT_ID}:{CLIENT_SECRET}"
    b64   = base64.b64encode(creds.encode()).decode()
    return f"Basic {b64}"

@app.route("/oauth/callback")
def oauth_callback():
    """Rota de callback OAuth2: troca code por access_token."""
    code = request.args.get("code")
    if not code:
        return "Código não fornecido.", 400

    resp = httpx.post(
        "https://api.bling.com.br/Api/v3/oauth/token",
        headers={
            "Authorization": get_basic_auth_header(),
            "Content-Type":  "application/x-www-form-urlencoded",
            "Accept":        "1.0"
        },
        data={
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": REDIRECT_URI
        }
    )
    if resp.status_code != 200:
        return f"Erro ao obter token: {resp.text}", 500

    data = resp.json()
    with token_lock:
        token_data["access_token"]  = data["access_token"]
        token_data["refresh_token"] = data["refresh_token"]
        token_data["expires_at"]    = time.time() + data["expires_in"] - 60

    return "<h1>Token obtido com sucesso!</h1><p>Feche esta aba.</p>"

def refresh_access_token():
    """Renova o access token usando o refresh token."""
    with token_lock:
        refresh_token = token_data["refresh_token"]

    resp = httpx.post(
        "https://api.bling.com.br/Api/v3/oauth/token",
        headers={
            "Authorization": get_basic_auth_header(),
            "Content-Type":  "application/x-www-form-urlencoded",
            "Accept":        "1.0"
        },
        data={
            "grant_type":    "refresh_token",
            "refresh_token": refresh_token
        }
    )
    resp.raise_for_status()
    data = resp.json()
    with token_lock:
        token_data["access_token"]  = data["access_token"]
        token_data["refresh_token"] = data["refresh_token"]
        token_data["expires_at"]    = time.time() + data["expires_in"] - 60

def discount_loop():
    """Loop em background que aplica desconto a cada hora."""
    while True:
        with token_lock:
            token      = token_data["access_token"]
            expires_at = token_data["expires_at"]

        if not token:
            print("Aguardando obtenção do access_token…")
            time.sleep(5)
            continue

        if time.time() > expires_at:
            try:
                print("Renovando access_token…")
                refresh_access_token()
            except Exception as e:
                print("Falha ao renovar token:", e)
                time.sleep(60)
                continue

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json"
        }
        try:
            resp = httpx.get(API_URL, params={"filters": "situacao[3]"}, headers=headers)
            resp.raise_for_status()
            pedidos = resp.json().get("data", [])

            for pedido in pedidos:
                pid      = pedido["id"]
                itens    = pedido.get("itens", [])
                discounts = [{"id": item["id"], "desconto": 10} for item in itens]
                patch = httpx.patch(
                    f"{API_URL}/{pid}",
                    json={"itens": discounts},
                    headers=headers
                )
                patch.raise_for_status()
                print(f"[OK] Pedido {pid}: desconto aplicado")
        except Exception as ex:
            print("Erro no loop de desconto:", ex)

        time.sleep(3600)

if __name__ == "__main__":
    threading.Thread(target=discount_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=3000)
