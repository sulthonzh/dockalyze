# dockalyze

Dockerfile best practices analyzer. Zero dependencies.

Checks your Dockerfile for common mistakes and anti-patterns — the stuff that bloats images, breaks builds, or creates security risks.

## Install

```bash
npm install -g dockalyze
```

## Usage

```bash
# Analyze a Dockerfile
dockalyze Dockerfile

# Analyze all Dockerfiles in a directory
dockalyze .

# Pipe from stdin
cat Dockerfile | dockalyze -

# Current directory (auto-finds Dockerfile)
dockalyze
```

## What it checks

| Rule | Severity | What |
|------|----------|------|
| DL3000 | error | Missing FROM instruction |
| DL3001 | warning | Base image uses `:latest` — pin your tags |
| DL3002 | warning | No USER instruction — runs as root |
| DL3003 | info | No HEALTHCHECK defined |
| DL3004 | error | sudo in RUN — not needed, you're already root |
| DL3005 | warning | Multi-stage build without named stages |
| DL3006 | info | EXPOSE with privileged port (<1024) |
| DL3007 | info | ENV used only in build — use ARG instead |
| DL3009 | warning | apt-get update without install or cleanup |
| DL3010 | info | ADD instead of COPY for simple files |
| DL3014 | warning | apt-get without --no-install-recommends |
| DL3015 | error | apt-get install without -y |
| DL3059 | info | RUN could be combined with previous |
| DL4001 | warning | Piping curl to shell |

## Example output

```
$ dockalyze Dockerfile

  dockalyze — Dockerfile
  ──────────────────────────────────────────────────

  ✗ L5: apt-get install nodejs without -y will fail in non-interactive build
    [DL3015]

  ⚠ L1: Base image "ubuntu:latest" uses :latest tag — pin a specific version
    [DL3001]

  ⚠ L3: Use --no-install-recommends with apt-get to reduce image size
    [DL3014]

  ℹ No USER instruction — container will run as root
    [DL3002]

  ℹ No HEALTHCHECK defined — orchestration tools won't know if the app is healthy
    [DL3003]

  ──────────────────────────────────────────────────
  5 issues (1 error, 2 warnings, 2 infos)
```

## Exit codes

- `0` — no errors (warnings/info are ok)
- `1` — at least one error-level finding

Great for CI:

```yaml
# GitHub Actions
- name: Lint Dockerfile
  run: npx dockalyze Dockerfile
```

## Why

Because hadolint requires Haskell to build, and sometimes you just need a quick check without installing Docker Desktop extensions. This runs anywhere Node runs, checks the important stuff, and gets out of your way.

## License

MIT
