set -e
getent group iohr-agent >/dev/null || groupadd -r iohr-agent
getent passwd iohr-agent >/dev/null || useradd -r -g iohr-agent -d /var/lib/iohr-agent -s /sbin/nologin iohr-agent
# Read the capture companion's counts, if it is installed.
if getent group iohr-capture-read >/dev/null && ! id -nG iohr-agent | grep -qw iohr-capture-read; then
  usermod -a -G iohr-capture-read iohr-agent
  if command -v systemctl >/dev/null && systemctl is-active --quiet iohr-agent 2>/dev/null; then
    echo "iohr-agent: the agent's user joined iohr-capture-read; restart the agent to read capture counts: sudo systemctl restart iohr-agent"
  fi
fi
