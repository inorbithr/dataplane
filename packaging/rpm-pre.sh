getent group iohr-agent >/dev/null || groupadd -r iohr-agent
getent passwd iohr-agent >/dev/null || useradd -r -g iohr-agent -d /var/lib/iohr-agent -s /sbin/nologin iohr-agent
exit 0
