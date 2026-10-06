getent group iohr-agent >/dev/null || groupadd -r iohr-agent
getent group iohr-capture >/dev/null || groupadd -r iohr-capture
getent passwd iohr-capture >/dev/null || useradd -r -g iohr-capture -d /nonexistent -s /sbin/nologin iohr-capture
exit 0
