#!/bin/sh
# Runs the InOrbit agent under launchd (hr.inorbit.agent.plist). Exit codes follow
# `iohr-agent run`: 2 is a configuration or policy error, 3 means the platform revoked
# this agent. On 3 the enrollment is set aside, so launchd's PathState stops restarting it;
# enrolling again creates a new one.
set -u
iohr="${IOHR:-iohr}"
state="$(dirname "$IOHR_AGENT_CONFIG")/state"
"$iohr" agent --config "$IOHR_AGENT_CONFIG" run
code=$?
if [ "$code" -eq 3 ] && [ -f "$state/enrollment.json" ]; then
  mv "$state/enrollment.json" "$state/enrollment.revoked-$(date +%Y%m%dT%H%M%S).json"
  echo "iohr-agent-launchd: revoked by the platform; enroll again to restart" >&2
fi
exit "$code"
