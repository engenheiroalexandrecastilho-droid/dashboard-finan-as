# Minhas Finanças

Dashboard (PWA, mobile-first) de gastos a partir do Open Finance via Belvo, com visões separadas de
**Pessoal** e **Empresa**. Publicado no GitHub Pages.

## Segurança (repositório público)
Os dados financeiros **nunca** ficam em texto puro aqui. `site/data/transactions.enc.json` é cifrado
(PBKDF2-SHA256 600k iterações + AES-256-GCM) e só abre no navegador com a senha. Regras pessoais, CPF e
credenciais ficam em *Secrets* do GitHub. Não commite `data/`, `.tsv` ou qualquer export bancário.

## Como funciona
- `scripts/fetch_belvo.py` — coleta transações no Belvo (`data/raw.json`, ignorado pelo git).
- `scripts/build.py` — classifica e gera o arquivo cifrado.
- `.github/workflows/update.yml` — todo dia: coleta, cifra e publica no Pages.
- `site/` — o app (HTML estático + service worker).

## Configuração (uma vez)
1. Settings → Pages → Source: **GitHub Actions**.
2. Settings → Secrets and variables → Actions → crie:
   - `DASH_PASSPHRASE` — a senha do dashboard
   - `BELVO_SECRET_ID`, `BELVO_SECRET_PASSWORD` — chaves da API Belvo
   - `OWNER_CPF`, `OWNER_NAME` — para reconhecer transferências para si mesmo
   - `EXTRA_RULES` — JSON `[["regex","Nome","Categoria"], ...]` com regras de comerciantes
3. Actions → *Atualizar e publicar dashboard* → Run workflow; confira o log da coleta
   (`fetch_belvo.py` ainda não foi validado contra a API real: ajuste `FETCH_PATH`/`DATE_PARAM` se preciso).

Sem as chaves do Belvo, o workflow publica o último arquivo cifrado que está no repositório.
