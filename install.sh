#!/usr/bin/env bash
# Corp-DFIR — instalador para Ubuntu (máquina de gestão na rede local).
# Uso: sudo ./install.sh [IP_DO_SERVIDOR]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$ROOT/deploy"
IP="${1:-$(hostname -I | awk '{print $1}')}"
PORT="${DFIR_PORT:-8443}"

[ "$(id -u)" -eq 0 ] || { echo "Rode com sudo."; exit 1; }

if ! command -v docker >/dev/null 2>&1; then
  echo "==> Instalando Docker"
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl openssl
  curl -fsSL https://get.docker.com | sh
fi
command -v openssl >/dev/null || apt-get install -y -qq openssl

mkdir -p "$DEPLOY/data" "$DEPLOY/certs"
chown -R 10001:10001 "$DEPLOY/data"
chmod 700 "$DEPLOY/data"

if [ ! -f "$DEPLOY/certs/server.crt" ]; then
  echo "==> Gerando certificado autoassinado para $IP (validade 3 anos)"
  openssl req -x509 -newkey rsa:3072 -nodes -days 1095 \
    -keyout "$DEPLOY/certs/server.key" -out "$DEPLOY/certs/server.crt" \
    -subj "/CN=corp-dfir" -addext "subjectAltName=IP:$IP,DNS:corp-dfir" >/dev/null 2>&1
  chmod 644 "$DEPLOY/certs/server.crt"
  chmod 640 "$DEPLOY/certs/server.key"
  chgrp 0 "$DEPLOY/certs/server.key"
fi

ENV_FILE="$DEPLOY/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "==> Gerando token de upload e senha do painel"
  TOKEN="$(openssl rand -hex 32)"
  PANEL_PASS="$(openssl rand -base64 18 | tr -d '/+=')"
  PANEL_HASH="$(docker run --rm caddy:2-alpine caddy hash-password --plaintext "$PANEL_PASS")"
  cat > "$ENV_FILE" <<EOF
DFIR_PORT=$PORT
DFIR_DATA_DIR=/data
DFIR_UPLOAD_TOKEN=$TOKEN
DFIR_PANEL_USER=dfir
DFIR_PANEL_HASH=$PANEL_HASH
REDIS_URL=redis://redis:6379/0
# CNPJs da própria empresa (separados por vírgula): certificados destes CNPJs não são "terceiros".
DFIR_OWN_CNPJS=
# Triagem por IA (opcional). Endpoint compatível com OpenAI, de preferência local.
LLM_BASE_URL=
LLM_API_KEY=
LLM_MODEL=
LLM_MIN_SCORE=5
EOF
  chmod 600 "$ENV_FILE"
  SHOW_PASS="$PANEL_PASS"
fi

echo "==> Subindo serviços"
( cd "$DEPLOY" && docker compose up -d --build )

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow "$PORT/tcp" >/dev/null && echo "==> Porta $PORT liberada no ufw"
fi

THUMB="$(openssl x509 -in "$DEPLOY/certs/server.crt" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
TOKEN_NOW="$(grep '^DFIR_UPLOAD_TOKEN=' "$ENV_FILE" | cut -d= -f2)"

for i in $(seq 1 30); do
  curl -fsk "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 2
done

cat <<EOF

================ Corp-DFIR instalado ================
Painel:        https://$IP:$PORT   (usuário: dfir)
EOF
[ -n "${SHOW_PASS:-}" ] && echo "Senha painel:  $SHOW_PASS   (mostrada só agora; guarde no cofre)"
cat <<EOF
Token upload:  $TOKEN_NOW
Thumbprint:    $THUMB

Tactical RMM > Script Arguments do Invoke-DfirCollect.ps1:
  -Server $IP -Port $PORT -Token $TOKEN_NOW -CertThumbprint $THUMB

Próximo passo: abra o painel > Configurações e informe os CNPJs da empresa
e, se quiser, a triagem por IA (ex.: OpenRouter https://openrouter.ai/api/v1).
=====================================================
EOF
