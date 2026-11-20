#!/usr/bin/env python3
"""Normaliza transações do Belvo e gera o arquivo CIFRADO site/data/transactions.enc.json.

Este repositório é público: nenhum dado financeiro em texto puro pode ser commitado.
O arquivo de saída é cifrado (PBKDF2-SHA256 600k + AES-256-GCM) com DASH_PASSPHRASE; o navegador
decifra com a senha digitada pelo usuário (WebCrypto).

Entrada:  data/raw.json (gerado por fetch_belvo.py; gitignored)  ou  SEED_FILE (TSV local, opcional)
Env:      DASH_PASSPHRASE (obrigatória), OWNER_CPF e OWNER_NAME (detectam transferências para si mesmo),
          EXTRA_RULES (JSON: [[regex, nome, categoria], ...] com regras pessoais de comerciantes)
"""
import base64, json, os, re, secrets, sys, unicodedata
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parent.parent
CFG = json.loads((ROOT / "config/connections.json").read_text())
CONN = {c["id"]: c for c in CFG["connections"]}
OWNER_CPF = os.environ.get("OWNER_CPF", "").strip()
OWNER_NAME = os.environ.get("OWNER_NAME", "").strip().lower()
SRC_SCOPE = {"NU": "pessoal", "XP": "pessoal", "PJ": "empresa"}
SRC_NAME = {"NU": "Nubank", "XP": "Banco XP", "PJ": "Nubank PJ"}

BELVO_CODE = {"FG": "Food & Groceries", "TT": "Transport & Travel", "TR": "Transfers",
              "PS": "Personal Shopping", "OP": "Online Platforms & Leisure", "BU": "Bills & Utilities",
              "HL": "Home & Life", "FE": "Fees & Charges", "IS": "Investments & Savings",
              "IN": "Insurance", "CL": "Credits & Loans", "IP": "Income & Payments"}
BELVO_MAP = {"Food & Groceries": "Alimentação", "Transport & Travel": "Transporte",
             "Personal Shopping": "Compras", "Online Platforms & Leisure": "Assinaturas e apps",
             "Bills & Utilities": "Contas", "Home & Life": "Casa e serviços", "Fees & Charges": "Taxas e IOF",
             "Insurance": "Casa e serviços", "Health": "Saúde", "Education": "Educação"}

def norm(s):
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().lower()
    return re.sub(r"\s+", " ", s).strip()

# Regras genéricas. As pessoais (comerciantes específicos) vêm de EXTRA_RULES e têm prioridade.
MERCHANTS = [
    (r"ifood", "iFood", "Delivery"),
    (r"uber|dl\*uberrides|dl \*uberrides", "Uber", "Transporte"),
    (r"posto |combustivel|indigo|estacionamento", None, "Transporte"),
    (r"panificadora|padaria|lanchonete|restaurante|cervejaria|supermercado|mercado ", None, "Alimentação"),
    (r"anthropic", "Claude (Anthropic)", "Assinaturas e apps"),
    (r"google|amazonprime|netflix|spotify", None, "Assinaturas e apps"),
    (r"ingresso\.com", "Ingresso.com", "Lazer e jogos"),
    (r"telefonica|energia|equatorial|claro|vivo|tim s", None, "Contas"),
    (r"iof|tarifa", "IOF / tarifas", "Taxas e IOF"),
]
PJ_RULES = [(r"ministerio da fazenda", "Receita Federal (impostos)", "Impostos")]
try:
    EXTRA = [tuple(r) for r in json.loads(os.environ.get("EXTRA_RULES") or "[]")]
except json.JSONDecodeError:
    sys.exit("EXTRA_RULES não é JSON válido")

def clean_name(desc):
    d = desc or ""
    d = re.sub(r"^(Transfer[eê]ncia (enviada|recebida)( pelo Pix)?\|?|Pix (enviado para|recebido de)|Pagamento (efetuado\||para ))\s*", "", d, flags=re.I)
    d = re.sub(r"\s+\d{11}$", "", d.strip())
    d = re.sub(r"^\d{2}\.\d{3}\.\d{3}\s+", "", d)
    if d.isupper() or d.islower():
        d = d.title()
    return d.strip()[:40] or "Sem descrição"

def classify(scope, io, desc, belvo_cat, doc):
    n = norm(desc)
    is_self = bool(OWNER_CPF and doc == OWNER_CPF) or bool(OWNER_NAME and OWNER_NAME in n)
    if re.search(r"aplicacao rdb|resgate rdb|rendimento", n):
        return "investimento", "Investimentos", clean_name(desc)
    if re.search(r"pagamento de fatura|pagamento para banco xp|pagamento recebido", n):
        return "interno", "Fatura de cartão", "Pagamento de fatura"
    if is_self:
        return ("retirada", "Retirada do sócio", "Retirada do sócio") if scope == "empresa" \
            else ("interno", "Entre minhas contas", "Transferência própria")
    if io == "INFLOW":
        return "receita", "Receita", clean_name(desc)
    if scope == "empresa":
        for rx, name, cat in PJ_RULES:
            if re.search(rx, n):
                return "gasto", cat, name
    for rx, name, cat in EXTRA + MERCHANTS:
        if re.search(rx, n):
            return "gasto", cat, name or clean_name(desc)
    if belvo_cat == "Transfers":
        return "gasto", "Pix a pessoas", clean_name(desc)
    return "gasto", BELVO_MAP.get(belvo_cat, "Outros"), clean_name(desc)

def load_live(path):
    out = []
    for t in json.loads(path.read_text()):
        conn = CONN.get(t.get("connection_id") or t.get("link"), {})
        amt = t.get("amount") or 0
        if t.get("currency", "BRL") != "BRL" and t.get("local_currency_amount"):
            amt = t["local_currency_amount"]
        cp = (t.get("counterparty") or {}).get("document_number")
        out.append(dict(id=t.get("transaction_id") or t.get("id"),
                        date=(t.get("date") or t.get("value_date") or t.get("accounting_date") or "")[:10],
                        amount=float(amt), io=t.get("type"), desc=t.get("description"),
                        belvo=t.get("category"), doc=cp, src=conn.get("name", "?"),
                        scope=conn.get("scope", "pessoal")))
    return out

def load_seed(path):
    out = []
    for i, line in enumerate(path.read_text().splitlines()):
        if not line.strip() or line.startswith("#"):
            continue
        d, amt, src, io, cat, desc = line.split("\t")
        out.append(dict(id=f"seed-{i}", date=d, amount=float(amt), io="OUTFLOW" if io == "O" else "INFLOW",
                        desc=desc, belvo=BELVO_CODE.get(cat), doc=None, src=SRC_NAME[src], scope=SRC_SCOPE[src]))
    return out

def encrypt(plain: bytes, passphrase: str) -> dict:
    salt, iv, iters = secrets.token_bytes(16), secrets.token_bytes(12), 600_000
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, iters).derive(passphrase.encode())
    ct = AESGCM(key).encrypt(iv, plain, None)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"v": 1, "iter": iters, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}

def main():
    passphrase = os.environ.get("DASH_PASSPHRASE")
    if not passphrase:
        sys.exit("DASH_PASSPHRASE ausente: sem ela não gero o arquivo cifrado.")
    live, seed = ROOT / "data/raw.json", os.environ.get("SEED_FILE")
    if live.exists():
        rows, partial = load_live(live), False
    elif seed:
        rows, partial = load_seed(Path(seed)), True
    else:
        print("Sem data/raw.json nem SEED_FILE: mantendo o arquivo cifrado que já existe.")
        return 0
    txns = []
    for r in rows:
        if not r["date"]:
            continue
        kind, cat, merchant = classify(r["scope"], r["io"], r["desc"], r["belvo"], r["doc"])
        txns.append(dict(id=r["id"], d=r["date"], v=round(r["amount"], 2), s=r["scope"], k=kind,
                         c=cat, m=merchant, a=r["src"]))
    txns.sort(key=lambda t: (t["d"], t["id"]), reverse=True)
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "data_through": txns[0]["d"] if txns else None, "partial": partial, "txns": txns}
    dest = ROOT / "site/data/transactions.enc.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(encrypt(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(), passphrase)))
    print(f"{len(txns)} transações cifradas -> {dest} (partial={partial})")

if __name__ == "__main__":
    sys.exit(main())
