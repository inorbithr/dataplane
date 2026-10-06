getent group iohr-agent >/dev/null || groupadd -r iohr-agent
getent passwd iohr-agent >/dev/null || useradd -r -g iohr-agent -d /var/lib/iohr-agent -s /sbin/nologin iohr-agent
# Read the capture companion's counts, if it is installed.
if getent group iohr-capture-read >/dev/null; then usermod -a -G iohr-capture-read iohr-agent; fi
exit 0
