# Vulnerability statements (OpenVEX)

`statements.json` lists, for known vulnerabilities in the agent's dependencies, whether
they affect the agent ([OpenVEX 0.2.0](https://github.com/openvex/spec)). Each release
attaches `iohr-agent.openvex.json`, made by `mise run dist:vex` from this file, so a
scanner can suppress what does not apply and flag what does.

A statement names the vulnerability, a status (`not_affected`, `affected`, `fixed`,
`under_investigation`) and, for `not_affected`, a justification from the OpenVEX list:

```json
[
  {
    "vulnerability": {"name": "CVE-2026-0000"},
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "impact_statement": "The agent never calls the affected function."
  }
]
```

An empty list means no known vulnerability has been assessed for this version.
