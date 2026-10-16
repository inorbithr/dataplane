# Gating a deploy on real checks: `iohr-agent run --once`

`run --once` runs the checks declared in `checks.toml` one time, from inside your network,
and exits with a code a pipeline can gate on. There is no daemon and no session, and
nothing is sent to InOrbit. The checks run under the same local policy, ceilings and
secret rules as the agent's jobs, through the same code.

```sh
iohr-agent run --once                                  # every declared check
iohr-agent run --once --check orders --check home      # only these
iohr-agent run --once --tag tier=front                 # only checks with this tag
iohr-agent run --once --format junit --out checks.xml  # JUnit for the CI's test view
iohr-agent run --once --evidence run.jws               # also the report, signed
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | every selected check passed (skipped ones don't count) |
| `1` | at least one check failed; with `--fail-on degraded`, also a check that passed above 80% of its `max_ms` |
| `2` | nothing failed, but something couldn't be judged: an unknown `--check` name, a refusal by a ceiling or a secret rule, a bad file, or the run's `--timeout` |

A failure always wins over an error, so a pipeline that stops on non-zero never mistakes
"could not tell" for "passed".

## What each entry comes to

| Entry | Outcome |
|---|---|
| `[[check]]` | `pass`, `degraded` (passed, close to `max_ms`), `fail`, or `error` |
| `[[refuse]] by = "policy"` | `pass` when this machine's policy refuses it before anything is sent; `fail` with `guard_open` when the policy would let it through |
| `[[refuse]]` with `expect` | an ordinary check whose expected answer is the refusal (e.g. `status = 401`) |
| `[[refuse]] by = "platform"` | `skipped`: the platform refuses those, not this machine |
| `hwmon` (host sensors) | `skipped`: they judge a window of readings, which the running agent keeps |

The report holds timings, status codes and error classes, never a response body or a
secret, the same as the agent's results.

## Formats

- `text` (default): one line per check and a summary.
- `json`: one document, with the agent's version, the policy's hash, counts and every check.
- `junit`: JUnit XML. Failures and errors show in the CI's test view; skipped checks are marked skipped.
- `sarif`: SARIF 2.1.0 for code-scanning views; only failures, errors and degraded checks.

## Evidence

`--evidence <file>` writes the JSON report as a compact JWS signed with this agent's key
(the key in `agent.toml`, the one the platform knows from enrollment). Anyone with the
agent's public key can check that this agent produced this report and that nothing in it
changed. Recording it on the platform as a verify record (PRD 0008) comes in a later
release.

## In a pipeline

The runner needs network access to the targets, so run it on a machine inside your
network (a self-hosted runner) where `iohr-agent` and its `agent.toml` are installed.

### GitHub Actions

```yaml
- name: Checks from inside the network
  run: iohr-agent run --once --format junit --out iohr-checks.xml --timeout 120
- name: Publish results
  if: always()
  uses: mikepenz/action-junit-report@v5
  with:
    report_paths: iohr-checks.xml
```

### GitLab CI

```yaml
verify:
  stage: verify
  tags: [inside-network]
  script:
    - iohr-agent run --once --format junit --out iohr-checks.xml
  artifacts:
    when: always
    reports:
      junit: iohr-checks.xml
```

### Jenkins

```groovy
stage('Verify') {
  steps {
    sh 'iohr-agent run --once --format junit --out iohr-checks.xml'
  }
  post {
    always { junit 'iohr-checks.xml' }
  }
}
```

### After a deploy, with a margin

```sh
# Give the rollout a minute, then fail the pipeline on a failed or slow check.
sleep 60 && iohr-agent run --once --tag tier=front --fail-on degraded
```
