#!/bin/bash
# Enable PERSIST_SESSIONS on the live auth server without dumping .env.
set -euo pipefail
cd /root/dragonite-auth
python3 - <<'PY'
from pathlib import Path
import re
p = Path(".env")
t = p.read_text()
if re.search(r"^PERSIST_SESSIONS=", t, re.M):
    t = re.sub(r"^PERSIST_SESSIONS=.*$", "PERSIST_SESSIONS=true", t, flags=re.M)
else:
    t = t.rstrip() + "\nPERSIST_SESSIONS=true\n"
p.write_text(t)
for line in p.read_text().splitlines():
    if line.startswith("PERSIST_SESSIONS="):
        print(line)
PY
node --check auth-server.js
node --check session-store.js
pm2 restart dragonite-auth --update-env
sleep 3
pm2 logs dragonite-auth --lines 50 --nostream
