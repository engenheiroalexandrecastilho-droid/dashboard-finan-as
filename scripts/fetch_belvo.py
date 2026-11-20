#!/usr/bin/env python3
"""Busca transações na API do Belvo e acumula em data/raw.json (dedupe por transaction_id).

Credenciais (GitHub Secrets): BELVO_SECRET_ID e BELVO_SECRET_PASSWORD. Sem elas, o script sai sem erro
e o dashboard continua com os dados que já existem.
Variáveis opcionais: BELVO_BASE_URL (padrão https://api.belvo.com), LOOKBACK_DAYS (padrão 400).

ATENÇÃO: escrito sem acesso à API do Belvo a partir do ambiente de desenvolvimento (host bloqueado).
Na primeira execução (Actions > Atualizar dashboard > Run workflow) confira o log: se o endpoint ou
os parâmetros de data do seu produto Open Finance forem diferentes, ajuste só FETCH_PATH / DATE_PARAM abaixo.
"""
import base64, json, os, sys, urllib.parse, urllib.request
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = os.environ.get("BELVO_BASE_URL", "https://api.belvo.com").rstrip("/")
FETCH_PATH = "/api/transactions/"      # ajustar se o produto Open Finance usar outro caminho
DATE_PARAM = "value_date__range"        # ajustar conforme a documentação do produto

def get(url, auth):
    req = urllib.request.Request(url, headers={"Authorization": auth, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def main():
    sid, pwd = os.environ.get("BELVO_SECRET_ID"), os.environ.get("BELVO_SECRET_PASSWORD")
    if not (sid and pwd):
        print("BELVO_SECRET_ID/PASSWORD ausentes: pulando coleta.")
        return 0
    auth = "Basic " + base64.b64encode(f"{sid}:{pwd}".encode()).decode()
    cfg = json.loads((ROOT / "config/connections.json").read_text())
    days = int(os.environ.get("LOOKBACK_DAYS", "400"))
    rng = f"{date.today() - timedelta(days=days)},{date.today()}"
    raw_path = ROOT / "data/raw.json"
    have = {t["transaction_id"]: t for t in json.loads(raw_path.read_text())} if raw_path.exists() else {}
    for c in cfg["connections"]:
        q = urllib.parse.urlencode({"link": c["id"], DATE_PARAM: rng, "page_size": 1000})
        url, n = f"{BASE}{FETCH_PATH}?{q}", 0
        while url:
            page = get(url, auth)
            for t in page.get("results", []):
                t["connection_id"] = c["id"]
                have[t["id"] if "id" in t else t["transaction_id"]] = t | {"transaction_id": t.get("id") or t.get("transaction_id")}
                n += 1
            url = page.get("next")
        print(f"{c['name']}: {n} transações")
    raw_path.parent.mkdir(exist_ok=True)
    raw_path.write_text(json.dumps(sorted(have.values(), key=lambda t: t.get("value_date") or t.get("date") or ""), ensure_ascii=False))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # não derruba o workflow: dashboard segue com dados anteriores
        print(f"ERRO na coleta: {e}")
        sys.exit(1)
