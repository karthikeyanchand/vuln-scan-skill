#!/usr/bin/env bash
# Preflight check for the workshop. Prints what is ready and what is missing.
PORT="${ANTARES_PORT:-8000}"
ok=0; warn=0

check() {  # name, command
  if command -v "$2" >/dev/null 2>&1; then
    printf '  \033[32m✔\033[0m %-12s %s\n' "$1" "$("$2" --version 2>/dev/null | head -1)"
    ok=$((ok+1))
  else
    printf '  \033[33m✘\033[0m %-12s not found\n' "$1"; warn=$((warn+1))
  fi
}

echo "Tools"
check python3 python3
check node node
check semgrep semgrep
check pip-audit pip-audit
check gitleaks gitleaks
check antares antares
check mlx-lm mlx_lm.server
check codex codex

echo; echo "Antares model server"
if curl -sf "http://127.0.0.1:$PORT/v1/models" >/dev/null; then
  printf '  \033[32m✔\033[0m server answering on 127.0.0.1:%s\n' "$PORT"
  antares models list 2>/dev/null | sed 's/^/    /'
else
  printf '  \033[33m✘\033[0m nothing on 127.0.0.1:%s. Start ./setup/serve_antares_mlx.sh, or run the skill with --no-antares\n' "$PORT"
  warn=$((warn+1))
fi

echo; echo "Skill"
for d in "./.agents/skills/vuln-scan" "$HOME/.agents/skills/vuln-scan"; do
  [[ -f "$d/SKILL.md" ]] && printf '  \033[32m✔\033[0m found at %s\n' "$d"
done

echo; echo "$ok ready, $warn missing. Missing tools reduce coverage but the skill still runs."
