#!/usr/bin/env bash
# Collects what is needed to explain an incident on a console (management) or gateway server,
# into one archive: system and network state, firewall, the console and gateway services or
# containers (status, logs, settings), their health, the configuration each gateway node runs, the
# console's view of its gateways (nodes, last push, deployed vs built configuration) and the TLS
# certificates of the ports. It finds by itself what runs here, so the same script serves both.
#
#   sudo bash postmortem.sh                  # the last 24 hours of logs
#   sudo bash postmortem.sh --since 2h       # or: --since "2026-11-15 10:00"
#   sudo bash postmortem.sh --out /root      # where the archive goes (default /tmp)
#
# Secrets stay out: settings whose name looks secret (password, secret, key, token...) are masked,
# private keys and connection credentials are never read out, and the gateway configuration is
# summarized, not copied. Read the archive before sending it anywhere all the same.
set -uo pipefail

SINCE="24h"
OUT_DIR=/tmp
CONSOLE_DOCKER_DIR=/opt/oauth-console-docker
CONSOLE_DIR=/opt/oauth-console/current
CONSOLE_ENV=/etc/oauth-console/console.env
GATEWAY_ENV=/etc/oauth-gateway/gateway.env

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE=${2:?--since needs a value}; shift 2 ;;
    --out) OUT_DIR=${2:?--out needs a value}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Run this script as root: sudo bash $0" >&2; exit 1; }

# journalctl takes "24h ago"; docker logs takes "24h" or a timestamp.
if [[ "$SINCE" =~ ^[0-9]+[smhd]$ ]]; then JOURNAL_SINCE="${SINCE%?} ${SINCE: -1} ago"; else JOURNAL_SINCE="$SINCE"; fi
JOURNAL_SINCE=${JOURNAL_SINCE/ s ago/ seconds ago}; JOURNAL_SINCE=${JOURNAL_SINCE/ m ago/ minutes ago}
JOURNAL_SINCE=${JOURNAL_SINCE/ h ago/ hours ago}; JOURNAL_SINCE=${JOURNAL_SINCE/ d ago/ days ago}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="postmortem-$(hostname -s)-${STAMP}"
WORK="$(mktemp -d)/${NAME}"
mkdir -p "$WORK"
info() { echo "==> $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# run FILE TITLE COMMAND...: appends the command's output (stdout and stderr) under a title.
run() {
  local file=$1 title=$2; shift 2
  {
    echo "### ${title}"
    echo "\$ $*"
    if declare -F "$1" >/dev/null; then "$@" 2>&1; else timeout 60 "$@" 2>&1; fi
    echo "(exit $?)"
    echo
  } >>"${WORK}/${file}"
}

# Prints an env file (KEY=VALUE lines) with the values of secret-looking settings masked.
redact_env() {
  sed -E 's/\r$//' | awk -F= '
    /^[[:space:]]*(#|$)/ { print; next }
    {
      key = $1; sub(/^[[:space:]]*(export[[:space:]]+)?/, "", key)
      value = substr($0, index($0, "=") + 1)
      if (toupper(key) ~ /PASS|SECRET|KEY|TOKEN|CREDENTIAL|PRIVATE|SEAL|SALT|DSN|COOKIE|AUTH/ && value != "")
        print key "=<masked, " length(value) " characters>"
      else
        print key "=" value
    }'
}

# ---------------------------------------------------------------------------------------------
# The gateway configuration a node runs, summarized: names, ports, paths and versions only.
# Read with node from stdin; the first argument is the configuration file.
# ---------------------------------------------------------------------------------------------
read -r -d '' GATEWAY_SUMMARY_JS <<'JS'
const fs = require('fs');
const crypto = require('crypto');
const file = process.argv[2] || require('path').join(process.env.GATEWAY_DATA_DIR || 'data', 'config.json');
let config;
try { config = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (error) { console.log(`No configuration readable at ${file}: ${error.message}`); process.exit(0); }
const stat = fs.statSync(file);
const cert = (pem) => {
  try {
    const x = new crypto.X509Certificate(pem);
    const days = Math.round((new Date(x.validTo) - Date.now()) / 86400000);
    return { subject: x.subject.replace(/\n/g, ', '), names: x.subjectAltName, validTo: x.validTo, daysLeft: days, issuer: x.issuer.replace(/\n/g, ', ') };
  } catch { return null; }
};
const host = (url) => { try { return new URL(url).host; } catch { return url ? '(not a URL)' : null; } };
const summary = {
  file, savedAt: stat.mtime.toISOString(),
  version: config.version, gateway: config.gateway && { id: config.gateway.id, name: config.gateway.name, nodeCount: config.gateway.nodeCount },
  issuer: config.issuer, audience: config.audience,
  tokenKeys: (config.tokenKeys || config.keys || []).map((key) => key.kid || key.id).filter(Boolean),
  management: config.management,
  handlers: (config.handlers || []).map((h) => ({
    name: h.name, port: h.port, protocol: h.protocol, nodes: h.nodes, homePath: h.homePath, flow: Boolean(h.flow),
    certificate: h.tls && h.tls.certificate ? cert(h.tls.certificate) : undefined,
  })),
  apis: (config.apis || []).map((a) => ({
    name: a.name, basePath: a.basePath, access: a.access || 'subscription', upstream: host(a.upstreamUrl), connectionId: a.connectionId,
    operations: (a.operations || []).length,
    publicOperations: (a.operations || []).filter((o) => o.access === 'public').map((o) => `${String(o.method).toUpperCase()} ${o.path}`),
    flow: a.flow ? a.flow.name || true : false,
  })),
  products: (config.products || []).map((p) => ({ name: p.name, apis: (p.apiIds || []).length, rateLimit: p.rateLimit && p.rateLimit.enabled ? `${p.rateLimit.requests}/${p.rateLimit.period}` : 'off' })),
  subscriptions: (config.subscriptions || []).map((s) => ({ application: s.application, clientId: s.clientId, products: (s.productIds || []).length })),
  connections: (config.connections || []).map((c) => ({ id: c.id, name: c.name, type: c.type, baseUrl: host(c.baseUrl || c.url) })),
  observability: config.observability && Object.fromEntries(Object.entries(config.observability).map(([k, v]) => [k, v && typeof v === 'object' ? ('enabled' in v ? { enabled: v.enabled } : '(object)') : v])),
};
console.log(JSON.stringify(summary, null, 2));
JS

# ---------------------------------------------------------------------------------------------
# The console's view of its gateways, read from its database with its own models. Run in the
# console's folder with its settings loaded.
# ---------------------------------------------------------------------------------------------
read -r -d '' CONSOLE_SUMMARY_JS <<'JS'
const path = require('path');
const dir = process.cwd();
const crypto = require('crypto');
(async () => {
  const models = require(path.join(dir, 'models'));
  const sequelize = require(path.join(dir, 'config/database'));
  const { Gateway, GatewayCredential, Api, ApiProduct, Organization, User } = models;
  const out = { at: new Date().toISOString() };
  try { out.counts = { organizations: await Organization.count(), users: await User.count(), apis: await Api.count(), products: await ApiProduct.count() }; } catch (error) { out.counts = `failed: ${error.message}`; }
  let build = null;
  try { ({ buildGatewayConfig: build } = require(path.join(dir, 'services/gatewayConfig'))); } catch { /* older console */ }
  const { gatewayIncludes } = require(path.join(dir, 'services/gatewayQueries'));
  out.gateways = [];
  for (const g of await Gateway.findAll({ include: gatewayIncludes })) {
    const entry = {
      name: g.name, id: g.id, publicUrl: g.publicUrl, catalog: g.catalog && g.catalog.name, autoPush: g.autoPush,
      lastPushedHash: g.lastPushedHash && g.lastPushedHash.slice(0, 12), lastPushedAt: g.lastPushedAt,
      nodes: (g.nodes || []).map((n) => ({
        name: n.name, mode: n.mode, host: n.host, url: n.url, portOffset: n.portOffset, softwareVersion: n.softwareVersion,
        configVersion: n.configVersion, lastSeenAt: n.lastSeenAt, lastPushStatus: n.lastPushStatus, lastPushAt: n.lastPushAt, lastError: n.lastError,
      })),
      handlers: (g.handlers || []).map((h) => {
        let certificate;
        try { if (h.certificatePem) { const x = new crypto.X509Certificate(h.certificatePem); certificate = { names: x.subjectAltName, validTo: x.validTo }; } } catch { /* unreadable */ }
        return { name: h.name, port: h.port, protocol: h.protocol, tlsMode: h.tlsMode, homePath: h.homePath, policy: h.policy && h.policy.name, nodeId: h.nodeId, certificate };
      }),
    };
    try {
      entry.credentials = (await GatewayCredential.findAll({ where: { gatewayId: g.id }, order: [['createdAt', 'DESC']], limit: 5 }))
        .map((c) => ({ source: c.source, validTo: c.validTo, revokedAt: c.revokedAt, fingerprint: String(c.fingerprint).slice(0, 23) }));
    } catch (error) { entry.credentials = `failed: ${error.message}`; }
    if (build) {
      try {
        const { hash, problems } = await build(g);
        entry.builtHash = hash && hash.slice(0, 12);
        entry.changesNotDeployed = Boolean(hash && g.lastPushedHash && hash !== g.lastPushedHash);
        entry.problems = (problems || []).map((p) => p.message || p);
      } catch (error) { entry.builtHash = `failed: ${error.message}`; }
    }
    out.gateways.push(entry);
  }
  console.log(JSON.stringify(out, null, 2));
  await sequelize.close();
})().catch((error) => { console.log(`Console summary failed: ${error.message}`); process.exit(0); });
JS

# TLS certificate an address presents (a port alone means 127.0.0.1): subject, names, issuer, dates.
port_certificate() {
  local address=$1
  [[ "$address" == *:* ]] || address="127.0.0.1:${address}"
  have openssl || { echo "openssl not installed"; return; }
  echo | timeout 10 openssl s_client -connect "$address" -servername localhost 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || echo "No TLS on ${address} (plain HTTP, or nothing listening)"
}

# ---------------------------------------------------------------------------------------------
info "System"
run system.txt "Clock (JWT checks fail when it is off)" bash -c 'date -u; timedatectl 2>/dev/null || true'
run system.txt "Host" bash -c 'hostname -f 2>/dev/null || hostname; uptime; cat /etc/os-release 2>/dev/null | head -4; uname -r'
run system.txt "Memory" free -m
run system.txt "Disks" df -h -x tmpfs -x devtmpfs -x overlay
run system.txt "Out of memory kills" bash -c "journalctl -k --since '${JOURNAL_SINCE}' --no-pager 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process' | tail -50 || true"

info "Network and firewall"
run network.txt "Addresses" ip -br addr
run network.txt "Routes" ip route
run network.txt "Listening ports" ss -tlnp
run network.txt "Connections per state" bash -c "ss -tan | awk 'NR>1 {print \$1}' | sort | uniq -c"
run network.txt "DNS" bash -c 'cat /etc/resolv.conf; grep -v "^#" /etc/hosts'
have iptables && run network.txt "iptables rules" iptables -S
have iptables && run network.txt "DOCKER-USER chain" iptables -L DOCKER-USER -n -v --line-numbers
have iptables && run network.txt "NAT (Docker published ports)" iptables -t nat -S
have ufw && run network.txt "ufw" ufw status verbose

if have docker; then
  info "Docker"
  run docker.txt "Version" docker version --format '{{.Server.Version}}'
  run docker.txt "Containers" docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
  run docker.txt "Images" docker images
  run docker.txt "Disk use" docker system df
fi

# ---------------------------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------------------------
# Gateway containers: the image name, or the GATEWAY_DATA_DIR its Dockerfile sets (as update.sh).
gateway_containers() {
  have docker || return 0
  local id
  for id in $(docker ps -aq 2>/dev/null); do
    docker inspect "$id" --format '{{.Name}}{{"\t"}}{{.Config.Image}}{{"\t"}}{{range .Config.Env}}{{.}} {{end}}'
  done | awk -F'\t' '{ sub(/^\//, "", $1) }
    $1 !~ /-previous$/ && ($2 ~ /oauth-(server-)?gateway/ || $3 ~ /(^| )GATEWAY_DATA_DIR=/) { print $1 }'
}

found_gateway=0
for name in $(gateway_containers); do
  found_gateway=1
  info "Gateway container ${name}"
  f="gateway-${name}.txt"
  run "$f" "State" docker inspect "$name" --format 'image={{.Config.Image}} created={{.Created}} started={{.State.StartedAt}} status={{.State.Status}} restarts={{.RestartCount}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} health={{if .State.Health}}{{.State.Health.Status}}{{end}}'
  run "$f" "Published ports (a handler's port missing here isn't reachable from outside the container)" docker port "$name"
  run "$f" "Mounts and restart policy" docker inspect "$name" --format '{{range .Mounts}}{{.Type}} {{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}} -> {{.Destination}}{{"\n"}}{{end}}restart={{.HostConfig.RestartPolicy.Name}} network={{.HostConfig.NetworkMode}}'
  {
    echo "### Settings"
    docker inspect "$name" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -E '^(GATEWAY_|NODE_)' | redact_env
    echo
  } >>"${WORK}/${f}"
  run "$f" "Health (/healthz, /readyz: configuration version and every handler's listening state)" docker exec "$name" node -e "
    const port = process.env.GATEWAY_HEALTH_PORT || 9080;
    (async () => { for (const p of ['/healthz', '/readyz']) { try { const r = await fetch('http://127.0.0.1:' + port + p); console.log(p, r.status, await r.text()); } catch (e) { console.log(p, 'failed', e.message); } } })();"
  run "$f" "Metrics (auth failures, rate limits, upstream errors, threats, policy errors)" docker exec "$name" node -e "
    fetch('http://127.0.0.1:' + (process.env.GATEWAY_HEALTH_PORT || 9080) + '/metrics').then((r) => r.text()).then((t) => console.log(t.split('\n').filter((l) => l && !l.startsWith('#') && /fail|error|limited|threat|status=\"[45]/.test(l)).join('\n') || '(none)')).catch((e) => console.log('failed', e.message));"
  echo "### Running configuration (summary)" >>"${WORK}/${f}"
  docker exec -i "$name" node - <<<"$GATEWAY_SUMMARY_JS" >>"${WORK}/${f}" 2>&1
  echo >>"${WORK}/${f}"
  run "$f" "Data folder" docker exec "$name" sh -c 'ls -la "${GATEWAY_DATA_DIR:-data}"'
  # Each published address (0.0.0.0 checked on 127.0.0.1; the IPv6 copies skipped).
  for address in $(docker port "$name" 2>/dev/null | sed -n 's/.*-> //p' | grep -v '^\[' | sed 's/^0\.0\.0\.0:/127.0.0.1:/' | sort -u); do
    run "$f" "TLS certificate on ${address}" port_certificate "$address"
  done
  info "  log of ${name} since ${SINCE}"
  docker logs --since "$SINCE" --timestamps "$name" >"${WORK}/gateway-${name}.log" 2>&1
  [[ -n "$(docker ps -aq --filter "name=^${name}-previous$")" ]] && run "$f" "Left-over previous container (a failed update)" docker ps -a --filter "name=^${name}-previous$"
done

if systemctl list-unit-files oauth-gateway.service >/dev/null 2>&1 && [[ -f /etc/systemd/system/oauth-gateway.service ]]; then
  found_gateway=1
  info "Gateway service"
  f=gateway-service.txt
  run "$f" "Status" systemctl status oauth-gateway --no-pager -l
  run "$f" "Release" bash -c 'readlink -f /opt/oauth-gateway/current; ls -1 /opt/oauth-gateway/releases 2>/dev/null | tail -5'
  [[ -f "$GATEWAY_ENV" ]] && run "$f" "Settings (${GATEWAY_ENV})" bash -c "$(declare -f redact_env); redact_env < '$GATEWAY_ENV'"
  data_dir="$(grep -E '^GATEWAY_DATA_DIR=' "$GATEWAY_ENV" 2>/dev/null | tail -1 | cut -d= -f2-)"
  data_dir="${data_dir:-/var/lib/oauth-gateway}"
  health_port="$(grep -E '^GATEWAY_HEALTH_PORT=' "$GATEWAY_ENV" 2>/dev/null | tail -1 | cut -d= -f2-)"
  run "$f" "Health" bash -c "curl -s -m 5 -w ' (%{http_code})\n' http://127.0.0.1:${health_port:-9080}/healthz; curl -s -m 5 -w ' (%{http_code})\n' http://127.0.0.1:${health_port:-9080}/readyz"
  if have node; then
    echo "### Running configuration (summary)" >>"${WORK}/${f}"
    node - "${data_dir}/config.json" <<<"$GATEWAY_SUMMARY_JS" >>"${WORK}/${f}" 2>&1
  fi
  run "$f" "Data folder" ls -la "$data_dir"
  journalctl -u oauth-gateway --since "$JOURNAL_SINCE" --no-pager -o short-iso >"${WORK}/gateway-service.log" 2>&1
fi

# ---------------------------------------------------------------------------------------------
# Console (management)
# ---------------------------------------------------------------------------------------------
found_console=0
if [[ -f /etc/systemd/system/oauth-console.service ]]; then
  found_console=1
  info "Console service"
  f=console-service.txt
  run "$f" "Status" systemctl status oauth-console --no-pager -l
  run "$f" "Release" bash -c 'readlink -f /opt/oauth-console/current; ls -1 /opt/oauth-console/releases 2>/dev/null | tail -5'
  [[ -f "$CONSOLE_ENV" ]] && run "$f" "Settings (${CONSOLE_ENV})" bash -c "$(declare -f redact_env); redact_env < '$CONSOLE_ENV'"
  port="$(grep -E '^PORT=' "$CONSOLE_ENV" 2>/dev/null | tail -1 | cut -d= -f2-)"
  link_port="$(grep -E '^GATEWAY_LINK_PORT=' "$CONSOLE_ENV" 2>/dev/null | tail -1 | cut -d= -f2-)"
  run "$f" "Answers on its port" curl -s -o /dev/null -m 10 -w '%{http_code} in %{time_total}s\n' "http://127.0.0.1:${port:-3000}/login"
  run "$f" "Gateway link certificate (port ${link_port:-3443})" port_certificate "${link_port:-3443}"
  if have node && [[ -d "$CONSOLE_DIR" ]]; then
    echo "### Gateways as the console sees them" >>"${WORK}/${f}"
    (cd "$CONSOLE_DIR" && set -a && . "$CONSOLE_ENV" && set +a && DOTENV_CONFIG_QUIET=true node - <<<"$CONSOLE_SUMMARY_JS") 2>&1 | grep -v '^Executing' >>"${WORK}/${f}"
  fi
  if have nginx; then
    run "$f" "nginx configuration test" nginx -t
    run "$f" "nginx errors" bash -c 'tail -n 200 /var/log/nginx/error.log 2>/dev/null'
    run "$f" "HTTPS certificate (443)" port_certificate 443
  fi
  journalctl -u oauth-console --since "$JOURNAL_SINCE" --no-pager -o short-iso >"${WORK}/console-service.log" 2>&1
fi

if have docker && [[ -f "${CONSOLE_DOCKER_DIR}/docker-compose.yml" ]]; then
  found_console=1
  info "Console Docker stack (${CONSOLE_DOCKER_DIR})"
  f=console-docker.txt
  compose=(docker compose --project-directory "$CONSOLE_DOCKER_DIR" -f "${CONSOLE_DOCKER_DIR}/docker-compose.yml")
  run "$f" "Services" "${compose[@]}" ps -a
  [[ -f "${CONSOLE_DOCKER_DIR}/console.env" ]] && run "$f" "Settings (console.env)" bash -c "$(declare -f redact_env); redact_env < '${CONSOLE_DOCKER_DIR}/console.env'"
  [[ -f "${CONSOLE_DOCKER_DIR}/.env" ]] && run "$f" "Stack settings (.env)" bash -c "$(declare -f redact_env); redact_env < '${CONSOLE_DOCKER_DIR}/.env'"
  console_container="$("${compose[@]}" ps -q console 2>/dev/null | head -1)"
  if [[ -n "$console_container" ]]; then
    echo "### Gateways as the console sees them" >>"${WORK}/${f}"
    docker exec -i -w /app -e DOTENV_CONFIG_QUIET=true "$console_container" node - <<<"$CONSOLE_SUMMARY_JS" 2>&1 | grep -v '^Executing' >>"${WORK}/${f}"
    run "$f" "Gateway link certificate (port 3443)" port_certificate 3443
  fi
  run "$f" "HTTPS certificate (443)" port_certificate 443
  for service in $("${compose[@]}" ps -a --services 2>/dev/null); do
    info "  log of ${service} since ${SINCE}"
    "${compose[@]}" logs --no-color --timestamps --since "$SINCE" "$service" >"${WORK}/console-docker-${service}.log" 2>&1
  done
fi

# ---------------------------------------------------------------------------------------------
{
  echo "Postmortem of $(hostname -f 2>/dev/null || hostname), collected $(date -u +%FT%TZ), logs since ${SINCE}"
  echo "Gateway found: $([[ $found_gateway -eq 1 ]] && echo yes || echo no)   Console found: $([[ $found_console -eq 1 ]] && echo yes || echo no)"
  echo
  echo "Where to look first:"
  echo "  system.txt       clock, memory, disks, out-of-memory kills"
  echo "  network.txt      addresses, listening ports, firewall (DOCKER-USER), Docker's published ports"
  echo "  gateway-*.txt    a node: published ports, health (configuration version, handlers listening),"
  echo "                   error metrics, the configuration it runs, handler certificates"
  echo "  gateway-*.log    a node's log: one JSON line per request (status, error, requestId, traceId)"
  echo "  console-*.txt    the console: settings, link certificate, and per gateway its nodes (last seen,"
  echo "                   last push, last error, configuration version) against the deployed and built hash"
  echo "  console-*.log    the console's log"
  echo
  echo "Secrets are masked, but read the files before sending the archive anywhere."
} >"${WORK}/README.txt"

[[ $found_gateway -eq 0 && $found_console -eq 0 ]] && echo "WARNING: neither a gateway nor a console was found here; only the system state was collected." >&2

mkdir -p "$OUT_DIR"
ARCHIVE="${OUT_DIR%/}/${NAME}.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$WORK")" "$NAME"
chmod 600 "$ARCHIVE"
rm -rf "$(dirname "$WORK")"
info "Written ${ARCHIVE} ($(du -h "$ARCHIVE" | cut -f1))"
