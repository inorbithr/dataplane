#!/bin/sh
# Install the InOrbit agent as a LaunchAgent for the signed-in macOS user, after
# `iohr ext install agent` and `iohr agent init --dir "$HOME/Library/Application Support/InOrbit"`.
#   sh packaging/macos/install.sh            install or update, and start
#   sh packaging/macos/install.sh --remove   stop and remove the service (keeps the config,
#                                            key and enrollment; delete them by hand)
# No sudo: everything lives in the user's Library.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
label="hr.inorbit.agent"
dir="$HOME/Library/Application Support/InOrbit"
plist="$HOME/Library/LaunchAgents/$label.plist"
domain="gui/$(id -u)"

say() { printf 'iohr-agent macOS: %s\n' "$*" >&2; }

if [ "${1:-}" = "--remove" ]; then
  launchctl bootout "$domain/$label" 2>/dev/null || true
  rm -f "$plist" "$dir/bin/iohr-agent-launchd.sh"
  say "stopped and removed $label; config and state kept in $dir"
  exit 0
fi

iohr="$(command -v iohr || true)"
[ -n "$iohr" ] || { say "error: iohr not found on PATH; install it first"; exit 1; }
"$iohr" ext list 2>/dev/null | grep -q '^agent ' || { say "error: run 'iohr ext install agent' first"; exit 1; }
[ -f "$dir/agent.toml" ] || { say "error: no $dir/agent.toml; run 'iohr agent init --dir \"$dir\"' first"; exit 1; }

mkdir -p "$dir/bin" "$HOME/Library/Logs/InOrbit" "$HOME/Library/LaunchAgents"
install -m 0755 "$here/iohr-agent-launchd.sh" "$dir/bin/iohr-agent-launchd.sh"
sed -e "s|@HOME@|$HOME|g" -e "s|@IOHR@|$iohr|g" "$here/$label.plist" > "$plist.tmp"
plutil -lint "$plist.tmp" >/dev/null
mv "$plist.tmp" "$plist"
launchctl bootout "$domain/$label" 2>/dev/null || true
launchctl bootstrap "$domain" "$plist"
say "installed $label (logs: ~/Library/Logs/InOrbit/agent.log)"
if [ -f "$dir/state/enrollment.json" ]; then
  say "enrolled: launchd keeps it running"
else
  say "not enrolled yet: it starts once state/enrollment.json exists ('iohr agent enroll'), then 'launchctl kickstart -k $domain/$label'"
fi
