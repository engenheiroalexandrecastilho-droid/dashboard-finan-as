#!/usr/bin/env python3
"""Mescla transações novas (formato Belvo, lidas pelo conector do Claude) no arquivo cifrado do site.

Uso: DASH_PASSPHRASE=... OWNER_NAME=... EXTRA_RULES='[...]' python scripts/merge_update.py novas.json

novas.json = lista de objetos com: transaction_id, connection_id, date, amount, currency,
local_currency_amount, type (INFLOW/OUTFLOW), category, description, counterparty.document_number.

Regras: une por transaction_id; cada linha real remove uma linha "seed-*" de mesma (data, valor, escopo),
já que a amostra inicial é parcial. Reescreve site/data/transactions.enc.json (cifrado, mesma senha).
"""
import base64, json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build  # reaproveita classify/encrypt/load_live

ENC = build.ROOT / "site/data/transactions.enc.json"

def decrypt(blob: dict, passphrase: str) -> dict:
    d = lambda k: base64.b64decode(blob[k])
    key = PBKDF2HMAC(hashes.SHA256(), 32, d("salt"), blob["iter"]).derive(passphrase.encode())
    return json.loads(AESGCM(key).decrypt(d("iv"), d("ct"), None))

def main():
    pw = os.environ.get("DASH_PASSPHRASE") or sys.exit("DASH_PASSPHRASE ausente")
    new_file = Path(sys.argv[1]) if len(sys.argv) > 1 else sys.exit("uso: merge_update.py novas.json")
    cur = decrypt(json.loads(ENC.read_text()), pw)
    txns = {t["id"]: t for t in cur["txns"]}
    rows = build.load_live(new_file)
    added = 0
    for r in rows:
        if not r["date"] or not r["id"]:
            continue
        kind, cat, merchant = build.classify(r["scope"], r["io"], r["desc"], r["belvo"], r["doc"])
        t = dict(id=r["id"], d=r["date"], v=round(r["amount"], 2), s=r["scope"], k=kind, c=cat, m=merchant, a=r["src"])
        if t["id"] not in txns:
            added += 1
            for sid, s in list(txns.items()):  # consome uma linha de amostra equivalente
                if sid.startswith("seed-") and (s["d"], s["v"], s["s"]) == (t["d"], t["v"], t["s"]):
                    del txns[sid]
                    break
        txns[t["id"]] = t
    out = sorted(txns.values(), key=lambda t: (t["d"], t["id"]), reverse=True)
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "data_through": out[0]["d"], "partial": any(t["id"].startswith("seed-") for t in out), "txns": out}
    ENC.write_text(json.dumps(build.encrypt(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(), pw)))
    print(f"{len(rows)} lidas, {added} novas, {len(out)} no total, partial={payload['partial']}")

if __name__ == "__main__":
    sys.exit(main())
