# Fails the installation when a user or group cannot be created (nothing is masked).
set -e
getent group iohr-capture-read >/dev/null || groupadd -r iohr-capture-read
getent group iohr-capture >/dev/null || groupadd -r iohr-capture
getent passwd iohr-capture >/dev/null || useradd -r -g iohr-capture -d /nonexistent -s /sbin/nologin iohr-capture
# The agent's user reads the companion's counts.
if getent passwd iohr-agent >/dev/null && ! id -nG iohr-agent | grep -qw iohr-capture-read; then
  usermod -a -G iohr-capture-read iohr-agent
  if command -v systemctl >/dev/null && systemctl is-active --quiet iohr-agent 2>/dev/null; then
    echo "iohr-capture: the agent's user joined iohr-capture-read; restart the agent to read capture counts: sudo systemctl restart iohr-agent"
  fi
fi
