#!/bin/sh
# installer-smoke.sh — install (and uninstall) Vanzik the way a user
# does, then check what the installer left behind. Run by
# .github/workflows/installer-smoke.yml.
#
#   MODE=published  the public one-liner: .../releases/latest/download/install.sh | sh
#   MODE=local      this checkout's scripts/install.sh, installing WANT_VERSION
#                   (how a pull request tests installer changes before release;
#                   the workflow serves archives built from the checkout and
#                   points VANZIK_DOWNLOAD_URL at them)
#   WANT_VERSION    the release that should end up installed, e.g. 2.0.0
#
# POSIX sh, like install.sh: it runs under dash, busybox and macOS's sh.
#
# Variables exported inside $(...) below are meant to last for that one
# installer run only, which is what SC2030/SC2031 warn about.
# shellcheck disable=SC2030,SC2031
set -eu

REPO="lictorate/vanzik"
URL="https://github.com/$REPO/releases/latest/download/install.sh"
MODE="${MODE:-published}"
WANT="${WANT_VERSION:?set WANT_VERSION, e.g. 2.0.0}"
WANT="${WANT#v}"
HERE="$(cd "$(dirname "$0")" && pwd)"
export VANZIK_NO_UPDATE_CHECK=1

ok() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; exit 1; }
fetch() { # fetch <url> [<output file>]; stdout when no file is given
  if command -v curl >/dev/null 2>&1; then
    if [ $# -gt 1 ]; then curl -fsSL -o "$2" "$1"; else curl -fsSL "$1"; fi
  else
    if [ $# -gt 1 ]; then wget -q -O "$2" "$1"; else wget -qO- "$1"; fi
  fi
}
install_vanzik() { # runs the installer under test with the caller's env and options
  case "$MODE" in
    published) fetch "$URL" | sh -s -- "$@" ;;
    local) VANZIK_VERSION="$WANT" sh "$HERE/install.sh" "$@" ;;
    *) bad "MODE must be published or local, not $MODE" ;;
  esac
}
installer_source() {
  case "$MODE" in published) fetch "$URL" ;; *) cat "$HERE/install.sh" ;; esac
}

# Uninstall and the updated/downgraded/reinstalled messages arrived after the
# v1.2.0 installer; they are checked only when the installer under test has
# them (this checkout's always does; a published one from v1.2.0 does not).
if installer_source | grep -q VANZIK_UNINSTALL; then newer=1; else newer=""; fi

echo "== $MODE installer, $(uname -s) $(uname -m), user $(id -un), expecting $WANT"

# 1. Fresh install.
out="$(install_vanzik 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
echo "$out" | sed 's/^/    | /'
if echo "$out" | grep -q "Checksum verified"; then ok "checksum verified"; else bad "no 'Checksum verified' line"; fi
if echo "$out" | grep -q "Installed Vanzik $WANT"; then ok "installed $WANT"; else bad "no 'Installed Vanzik $WANT'"; fi

if [ "$(id -u)" = "0" ]; then
  dir=/usr/local/bin conf=/etc/vanzik
else
  dir="$HOME/.local/bin" conf="${XDG_CONFIG_HOME:-$HOME/.config}/vanzik"
fi

# 2. All three binaries, runnable, at the expected version.
for t in vanzik vanzik-mcp-gateway vanzik-llm-proxy; do
  if [ -x "$dir/$t" ]; then ok "$dir/$t is executable"; else bad "missing $dir/$t"; fi
done
v="$("$dir/vanzik" --version 2>&1)"
case "$v" in *"$WANT"*) ok "vanzik --version -> $v" ;; *) bad "version was: $v" ;; esac

# 3. The starter policy exists and validates.
if [ -f "$conf/default.yaml" ]; then ok "starter policy at $conf/default.yaml"; else bad "no starter policy in $conf"; fi
if "$dir/vanzik" validate --policy "$conf/default.yaml" >/dev/null 2>&1; then ok "starter policy validates"; else bad "starter policy failed validate"; fi

# 4. Running it again reinstalls cleanly and keeps the operator's policy.
printf '# operator edit\n' >> "$conf/default.yaml"
out2="$(install_vanzik 2>&1)" || { echo "$out2"; bad "second run exited non-zero"; }
if [ -n "$newer" ]; then again_line="Reinstalled Vanzik $WANT"; else again_line="Installed Vanzik $WANT"; fi
if echo "$out2" | grep -q "$again_line"; then ok "rerun: $again_line"; else echo "$out2"; bad "expected '$again_line' on rerun"; fi
if tail -n 1 "$conf/default.yaml" | grep -q "operator edit"; then ok "rerun kept the existing policy"; else bad "rerun overwrote the policy"; fi

# 5. The PATH hint names the file a zsh user's shell reads (macOS's default
#    shell never reads ~/.profile). Only the checkout's installer is held to
#    this; a published one predating the fix still says ~/.profile.
if [ "$MODE" = local ] && [ "$(id -u)" != "0" ]; then
  hint="$(PATH=/usr/bin:/bin SHELL=/bin/zsh VANZIK_VERSION="$WANT" /bin/sh "$HERE/install.sh" 2>&1)" || bad "zsh-hint run failed"
  if echo "$hint" | grep -q ">> ~/.zshrc"; then ok "PATH hint for a zsh user names ~/.zshrc"; else echo "$hint"; bad "zsh PATH hint wrong"; fi
fi

# 6. A tampered archive is refused and nothing is installed. Serving the
#    mirror from disk needs curl (busybox wget has no file:// support).
if command -v curl >/dev/null 2>&1; then
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; esac
  case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; esac
  archive="vanzik_${WANT}_${os}_${arch}.tar.gz"
  mirror="$(mktemp -d)" target="$(mktemp -d)"
  src="${VANZIK_DOWNLOAD_URL:-https://github.com/$REPO/releases/download/v$WANT}"
  fetch "$src/$archive" "$mirror/$archive"
  fetch "$src/checksums.txt" "$mirror/checksums.txt"
  printf 'tampered' >> "$mirror/$archive"
  # Exported in a subshell: an assignment before a function call is not
  # reliably passed on to the commands inside it in every POSIX shell.
  if tout="$(export VANZIK_DOWNLOAD_URL="file://$mirror" VANZIK_INSTALL_DIR="$target"; install_vanzik 2>&1)"; then
    echo "$tout"; bad "installer accepted a tampered archive"
  fi
  if echo "$tout" | grep -q "checksum mismatch"; then ok "tampered archive refused (checksum mismatch)"; else echo "$tout"; bad "refused, but not for the checksum"; fi
  if [ ! -e "$target/vanzik" ]; then ok "nothing installed from the tampered archive"; else bad "a binary was installed"; fi
else
  echo "SKIP  tamper check (needs curl for a file:// mirror)"
fi

# 7. The installer says whether it updated, downgraded (with a warning) or
#    reinstalled, judged by the version the binary already there reports. A
#    stub that prints a chosen version stands in for an older or newer release.
if [ -n "$newer" ]; then
  stub="$(mktemp -d)"
  printf '#!/bin/sh
echo "vanzik 9.9.9"
' > "$stub/vanzik"
  chmod +x "$stub/vanzik"
  sout="$(export VANZIK_INSTALL_DIR="$stub"; install_vanzik 2>&1)" || { echo "$sout"; bad "install over a 9.9.9 stub failed"; }
  if echo "$sout" | grep -q "Downgraded Vanzik 9.9.9 -> $WANT"; then ok "over 9.9.9: Downgraded 9.9.9 -> $WANT"; else echo "$sout"; bad "no Downgraded line"; fi
  if echo "$sout" | grep -q "^Warning: $WANT is older than the 9.9.9 you had"; then ok "downgrade warns"; else echo "$sout"; bad "no downgrade warning"; fi

  printf '#!/bin/sh
echo "vanzik 0.1.0"
' > "$stub/vanzik"
  sout="$(export VANZIK_INSTALL_DIR="$stub"; install_vanzik 2>&1)" || { echo "$sout"; bad "install over a 0.1.0 stub failed"; }
  if echo "$sout" | grep -q "Updated Vanzik 0.1.0 -> $WANT"; then ok "over 0.1.0: Updated 0.1.0 -> $WANT"; else echo "$sout"; bad "no Updated line"; fi
  if echo "$sout" | grep -q "^Warning:"; then echo "$sout"; bad "an update must not warn"; fi
  rm -rf "$stub"
fi

# 8. Uninstall removes the three binaries and keeps the policy, saying where;
#    a second run finds nothing and still succeeds; the environment variable
#    works like the flag; --purge also deletes the policy folder; --purge on
#    its own is refused.
if [ -n "$newer" ]; then
  uout="$(install_vanzik --uninstall 2>&1)" || { echo "$uout"; bad "uninstall exited non-zero"; }
  echo "$uout" | sed 's/^/    | /'
  for t in vanzik vanzik-mcp-gateway vanzik-llm-proxy; do
    if [ ! -e "$dir/$t" ]; then ok "uninstall removed $t"; else bad "uninstall left $dir/$t"; fi
  done
  if [ -f "$conf/default.yaml" ] && echo "$uout" | grep -q "Kept your policy folder $conf"; then
    ok "uninstall kept the policy and said where"
  else
    bad "uninstall did not keep or name the policy folder"
  fi
  uout2="$(install_vanzik --uninstall 2>&1)" || { echo "$uout2"; bad "second uninstall exited non-zero"; }
  if echo "$uout2" | grep -q "not installed in $dir"; then ok "second uninstall: nothing to remove, exit 0"; else echo "$uout2"; bad "second uninstall output"; fi

  install_vanzik >/dev/null 2>&1 || bad "reinstall before the VANZIK_UNINSTALL=1 check failed"
  eout="$(export VANZIK_UNINSTALL=1; install_vanzik 2>&1)" || { echo "$eout"; bad "VANZIK_UNINSTALL=1 exited non-zero"; }
  if [ ! -e "$dir/vanzik" ] && echo "$eout" | grep -q "Removed vanzik"; then ok "VANZIK_UNINSTALL=1 uninstalls"; else echo "$eout"; bad "VANZIK_UNINSTALL=1 did not uninstall"; fi

  install_vanzik >/dev/null 2>&1 || bad "reinstall before the --purge check failed"
  pout="$(install_vanzik --uninstall --purge 2>&1)" || { echo "$pout"; bad "--uninstall --purge exited non-zero"; }
  if [ ! -e "$dir/vanzik" ] && [ ! -e "$conf" ]; then ok "--purge removed the binaries and $conf"; else echo "$pout"; bad "--purge left files behind"; fi

  if mout="$(install_vanzik --purge 2>&1)"; then echo "$mout"; bad "--purge without --uninstall was accepted"; fi
  if echo "$mout" | grep -q "only applies together with --uninstall"; then ok "--purge on its own is refused"; else echo "$mout"; bad "--purge on its own: wrong message"; fi
fi

# 9. Over an AgentGuard 1.x install (this project's name before 2.0), the
#    installer moves it to Vanzik: the config and data folders byte for
#    byte, the database renamed, setup.json's paths, and the coding agents'
#    hooks pointed at vanzik with the old files kept as .vanzik-backup. It
#    runs in a home of its own; as root the migration changes nothing.
if [ "$(id -u)" != "0" ] && installer_source | grep -q 'migrate --from-agentguard'; then
  home="$(mktemp -d)"
  cfg="$home/.config" data="$home/.local/share" bin="$home/.local/bin"
  mkdir -p "$cfg/agentguard" "$data/agentguard" "$bin" "$home/.claude" "$home/.cursor"
  printf 'version: "1"\nname: operator policy\n' > "$cfg/agentguard/default.yaml"
  printf 'k3y\n' > "$cfg/agentguard/api-key"
  chmod 600 "$cfg/agentguard/api-key"
  printf '{"port":8080,"policy":"%s","data_dir":"%s","api_key":true,"login_start":false}\n' \
    "$cfg/agentguard/default.yaml" "$data/agentguard" > "$cfg/agentguard/setup.json"
  printf 'db' > "$data/agentguard/agentguard.db"
  printf '{"seq":1}\n' > "$data/agentguard/audit.jsonl"
  printf '#!/bin/sh\necho "agentguard 1.4.0"\n' > "$bin/agentguard"
  chmod +x "$bin/agentguard"
  # The hooks as AgentGuard 1.x's setup wrote them: Claude Code failing
  # closed, Cursor open, next to a hook of the user's own.
  cat > "$home/.claude/settings.json" <<EOF
{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"./mine.sh"}]},{"matcher":"Bash","hooks":[{"type":"command","command":"\"$bin/agentguard\" hook claude-code --fail-closed","timeout":330}]}]}}
EOF
  cat > "$home/.cursor/hooks.json" <<EOF
{"version":1,"hooks":{"beforeShellExecution":[{"command":"\"$bin/agentguard\" hook cursor","timeout":330}]}}
EOF
  claude_before="$(cat "$home/.claude/settings.json")"

  # Only HOME: every agent and XDG folder defaults under it.
  mig="$(
    HOME="$home"
    export HOME
    unset XDG_CONFIG_HOME XDG_DATA_HOME CLAUDE_CONFIG_DIR CURSOR_CONFIG_DIR GEMINI_CLI_HOME CODEX_HOME VANZIK_INSTALL_DIR
    install_vanzik 2>&1
  )" || { echo "$mig"; bad "install over an AgentGuard 1.x setup exited non-zero"; }
  echo "$mig" | sed 's/^/    | /'

  [ "$(cat "$cfg/vanzik/api-key" 2>/dev/null)" = k3y ] && ok "API key moved to $cfg/vanzik" || bad "API key not in $cfg/vanzik"
  grep -q 'operator policy' "$cfg/vanzik/default.yaml" 2>/dev/null && ok "the operator's policy moved, not the starter one" || bad "policy not moved"
  if grep -q "$cfg/vanzik/default.yaml" "$cfg/vanzik/setup.json" && grep -q "$data/vanzik" "$cfg/vanzik/setup.json"; then
    ok "setup.json points into the new folders"
  else
    cat "$cfg/vanzik/setup.json"; bad "setup.json still points at the old folders"
  fi
  if [ -f "$data/vanzik/vanzik.db" ] && [ ! -e "$data/vanzik/agentguard.db" ] && [ ! -e "$data/agentguard" ]; then
    ok "database renamed to vanzik.db in $data/vanzik"
  else
    bad "database or data folder not moved"
  fi
  [ "$(cat "$data/vanzik/audit.jsonl")" = '{"seq":1}' ] && ok "audit log moved unchanged" || bad "audit log changed"
  [ -L "$cfg/agentguard" ] && ok "$cfg/agentguard links to the new folder" || bad "no link left at $cfg/agentguard"
  if grep -q "bin/vanzik\\\\\" hook claude-code --fail-closed" "$home/.claude/settings.json" && grep -q './mine.sh' "$home/.claude/settings.json"; then
    ok "Claude Code's hook runs vanzik, still failing closed, beside the user's own"
  else
    cat "$home/.claude/settings.json"; bad "Claude Code's hook not rewritten"
  fi
  grep -q "bin/vanzik\\\\\" hook cursor\"" "$home/.cursor/hooks.json" && ok "Cursor's hook runs vanzik" || { cat "$home/.cursor/hooks.json"; bad "Cursor's hook not rewritten"; }
  [ "$(cat "$home/.claude/settings.json.vanzik-backup")" = "$claude_before" ] && ok "the old settings are kept as .vanzik-backup" || bad "no backup of the old settings"

  again="$(HOME="$home"; export HOME; unset XDG_CONFIG_HOME XDG_DATA_HOME CLAUDE_CONFIG_DIR CURSOR_CONFIG_DIR GEMINI_CLI_HOME CODEX_HOME; "$bin/vanzik" migrate --from-agentguard 2>&1)" || { echo "$again"; bad "second migration exited non-zero"; }
  echo "$again" | grep -q "nothing to migrate" && ok "a second migration finds nothing to do" || { echo "$again"; bad "second migration did something"; }
  rm -rf "$home"
fi

echo "ALL PASS"
