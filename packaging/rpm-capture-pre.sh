getent group iohr-capture-read >/dev/null || groupadd -r iohr-capture-read
getent group iohr-capture >/dev/null || groupadd -r iohr-capture
getent passwd iohr-capture >/dev/null || useradd -r -g iohr-capture -d /nonexistent -s /sbin/nologin iohr-capture
# The agent's user reads the companion's counts.
if getent passwd iohr-agent >/dev/null; then usermod -a -G iohr-capture-read iohr-agent; fi
exit 0
