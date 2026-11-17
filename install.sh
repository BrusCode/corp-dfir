#!/usr/bin/env bash
# Corp-DFIR — instalador para Ubuntu (máquina de gestão na rede local).
# Uso: sudo ./install.sh [IP_DO_SERVIDOR] [--reset-password]
# Pode ser executado de novo a qualquer momento: reaproveita token, porta e certificado.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$ROOT/deploy"
ENV_FILE="$DEPLOY/.env"
RESET_PASSWORD=0
IP=""
for arg in "$@"; do
  case "$arg" in
    --reset-password) RESET_PASSWORD=1 ;;
    *) IP="$arg" ;;
  esac
done
IP="${IP:-$(hostname -I | awk '{print $1}')}"
PORT_START=8443
PORT_END=8543

[ "$(id -u)" -eq 0 ] || { echo "Rode com sudo."; exit 1; }

if ! command -v docker >/dev/null 2>&1; then
  echo "==> Instalando Docker"
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl openssl
  curl -fsSL https://get.docker.com | sh
fi
command -v openssl >/dev/null || apt-get install -y -qq openssl

env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- | sed "s/^'//; s/'$//"; }
env_set() {
  # Replace or append KEY=VALUE without sed escaping issues (values may contain $ / &).
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  grep -vE "^$key=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$key" "$value" >> "$tmp"
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
}

port_is_ours() {
  docker ps --filter "name=corp-dfir-caddy" --format '{{.Ports}}' 2>/dev/null | grep -q ":$1->"
}
port_in_use() {
  ss -ltnH "sport = :$1" 2>/dev/null | grep -q . && return 0
  docker ps --format '{{.Ports}}' 2>/dev/null | grep -qE "(^|[ ,:])$1->" && return 0
  return 1
}
pick_port() {
  local wanted="$1" p
  if [ -n "$wanted" ] && { port_is_ours "$wanted" || ! port_in_use "$wanted"; }; then
    echo "$wanted"; return
  fi
  for p in $(seq "$PORT_START" "$PORT_END"); do
    if port_is_ours "$p" || ! port_in_use "$p"; then echo "$p"; return; fi
  done
  echo "Nenhuma porta livre entre $PORT_START e $PORT_END." >&2
  exit 1
}

new_panel_password() {
  PANEL_PASS="$(openssl rand -base64 18 | tr -d '/+=')"
  PANEL_HASH="$(docker run --rm caddy:2-alpine caddy hash-password --plaintext "$PANEL_PASS")"
  # Single quotes: Compose must not interpolate the "$" inside the bcrypt hash.
  env_set DFIR_PANEL_HASH "'$PANEL_HASH'"
  SHOW_PASS="$PANEL_PASS"
}

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

if [ ! -f "$ENV_FILE" ]; then
  echo "==> Gerando token de upload"
  cat > "$ENV_FILE" <<EOF
DFIR_DATA_DIR=/data
DFIR_UPLOAD_TOKEN=$(openssl rand -hex 32)
DFIR_PANEL_USER=dfir
REDIS_URL=redis://redis:6379/0
# Padrões; o painel (Configurações) sobrepõe estes valores.
DFIR_OWN_CNPJS=
LLM_BASE_URL=
LLM_API_KEY=
LLM_MODEL=
LLM_MIN_SCORE=5
EOF
  chmod 600 "$ENV_FILE"
fi

# Senha do painel: nova instalação, pedido explícito, ou hash gravado sem aspas
# (versões anteriores deixavam o Compose corromper o "$" do bcrypt).
if [ "$RESET_PASSWORD" -eq 1 ] || ! grep -qE "^DFIR_PANEL_HASH='\\\$2" "$ENV_FILE"; then
  echo "==> Gerando senha do painel"
  new_panel_password
fi

# Porta: mantém a gravada; se estiver ocupada por outro serviço, usa a próxima livre e grava.
SAVED_PORT="$(env_get DFIR_PORT)"
PORT="$(pick_port "${SAVED_PORT:-$PORT_START}")"
if [ "$PORT" != "$SAVED_PORT" ]; then
  [ -n "$SAVED_PORT" ] && echo "==> Porta $SAVED_PORT ocupada por outro serviço; usando $PORT"
  env_set DFIR_PORT "$PORT"
fi

echo "==> Subindo serviços (porta $PORT)"
( cd "$DEPLOY" && docker compose up -d --build --remove-orphans )

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow "$PORT/tcp" >/dev/null && echo "==> Porta $PORT liberada no ufw"
fi

THUMB="$(openssl x509 -in "$DEPLOY/certs/server.crt" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
TOKEN_NOW="$(env_get DFIR_UPLOAD_TOKEN)"

HEALTH="falhou"
for _ in $(seq 1 30); do
  if curl -fsk "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then HEALTH="ok"; break; fi
  sleep 2
done

cat <<EOF

================ Corp-DFIR instalado ================
Painel:        https://$IP:$PORT   (usuário: dfir)   [saúde: $HEALTH]
EOF
if [ -n "${SHOW_PASS:-}" ]; then
  echo "Senha painel:  $SHOW_PASS   (mostrada só agora; guarde no cofre)"
else
  echo "Senha painel:  inalterada (para gerar outra: sudo ./install.sh $IP --reset-password)"
fi
cat <<EOF
Token upload:  $TOKEN_NOW
Thumbprint:    $THUMB

Tactical RMM > Script Arguments do Invoke-DfirCollect.ps1:
  -Server $IP -Port $PORT -Token $TOKEN_NOW -CertThumbprint $THUMB

Próximo passo: abra o painel > Configurações e informe os CNPJs da empresa
e, se quiser, a triagem por IA (ex.: OpenRouter https://openrouter.ai/api/v1).
=====================================================
EOF
