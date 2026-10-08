#!/usr/bin/env bash
# Runs on the server. Usage: activate.sh /path/to/release.tar.gz
# Unpacks a new release, installs prod deps, switches the symlink, restarts, health-checks, rolls back on failure.
set -euo pipefail
APP=/opt/namuna
TARBALL="${1:?tarball}"
REL="$APP/releases/$(date +%Y%m%d%H%M%S)"
PREV="$(readlink -f $APP/current 2>/dev/null || true)"

mkdir -p "$REL" && tar -xzf "$TARBALL" -C "$REL"
cd "$REL" && npm ci --omit=dev --no-audit --no-fund
ln -sfn "$REL" $APP/current.new
mv -Tf $APP/current.new $APP/current
sudo systemctl restart namuna

for i in $(seq 1 20); do
  if curl -fsS http://127.0.0.1:3000/healthz >/dev/null 2>&1; then
    echo "healthy: $REL"
    rm -f "$TARBALL"
    ls -1dt $APP/releases/* | tail -n +6 | xargs -r rm -rf     # keep 5 releases
    exit 0
  fi
  sleep 1
done

echo "!! health check failed — rolling back" >&2
sudo journalctl -u namuna -n 30 --no-pager >&2 || true
if [ -n "$PREV" ] && [ -d "$PREV" ]; then
  ln -sfn "$PREV" $APP/current.new
  mv -Tf $APP/current.new $APP/current
  sudo systemctl restart namuna
fi
exit 1
