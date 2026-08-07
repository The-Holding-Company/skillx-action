# skillx verify — GitHub Action

Verify a signed agent **`SKILL.md`** (JWS + `did:web`) and scan it for prompt-injection
**before your pipeline or agent trusts it**. The CI-native companion to
[skillx.md](https://skillx.md/) — the trust layer for the agentic web.

Installing an unsigned skill is `curl | sudo bash` for your agent. This action makes
"only trust skills that verify" a one-line gate in any workflow.

> Outcomes are exact: **VERIFIED**, **UNSIGNED**, or **INVALID**. A tampered byte fails.
> INVALID always fails the job; UNSIGNED fails unless you opt in with `allow-unsigned`.

## Usage

```yaml
- uses: The-Holding-Company/skillx-action@v1
  with:
    skill-url: https://example.com/SKILL.md
```

That's the whole gate. If the skill doesn't verify, the step fails.

### Gate a PR that ships a skill

```yaml
name: verify-skill
on: [pull_request]
permissions:
  contents: read
jobs:
  skillx:
    runs-on: ubuntu-latest
    steps:
      - uses: The-Holding-Company/skillx-action@v1
        with:
          skill-url: https://example.com/SKILL.md
```

### Verify several skills

```yaml
jobs:
  skillx:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        skill:
          - https://username.md/SKILL.md
          - https://example.com/skills/foo/SKILL.md
    steps:
      - uses: The-Holding-Company/skillx-action@v1
        with:
          skill-url: ${{ matrix.skill }}
```

### Use the result without failing the build

```yaml
      - id: skillx
        uses: The-Holding-Company/skillx-action@v1
        with:
          skill-url: https://example.com/SKILL.md
          allow-unsigned: 'true'
      - run: echo "verification was ${{ steps.skillx.outputs.result }}"
```

## Inputs

| Input            | Default | Description                                                                                   |
| ---------------- | ------- | --------------------------------------------------------------------------------------------- |
| `skill-url`      | —       | **Required.** HTTPS URL (or local path) of the `SKILL.md` to verify.                          |
| `sig-url`        | `''`    | Signature location. Defaults to `<skill-url>.sig`.                                            |
| `jwk`            | `''`    | Path to a local public JWK to verify against, instead of resolving the publisher's `did:web`. |
| `scan`           | `true`  | Also run the prompt-injection content scan.                                                   |
| `allow-unsigned` | `false` | When `true`, an UNSIGNED result does not fail the job. INVALID always fails.                   |
| `python-version` | `3.12`  | Python version used to run the verifier.                                                      |

## Outputs

| Output   | Description                                       |
| -------- | ------------------------------------------------- |
| `result` | Exactly one of `VERIFIED`, `UNSIGNED`, `INVALID`. |

Every run also writes the full verifier output to the job's **step summary**.

## How it works

1. Resolves the publisher's public key from their own domain
   (`https://<domain>/.well-known/did.json`, W3C `did:web`) — the publisher's domain is
   the trust root, not skillx.
2. Checks the detached JWS (ES256) over the SHA-256 of the `SKILL.md`'s raw bytes.
3. Optionally scans the content for prompt-injection patterns (`scan: true`, default).

The verifier is the canonical [`skillx.py`](https://skillx.md/skillx.py), **vendored into
this action and pinned per release** so runs are reproducible and auditable — the action
never fetches a verifier at runtime. See [`skillx.py`](./skillx.py). Only the publisher's
`did:web` document is fetched over the network, from the publisher's own domain.

## Publish your own signed skill

Sign it, host it on your domain, submit one URL — see the three-step guide at
**<https://skillx.md/publish.html>**. Signing and verifying are free, forever.

## Roadmap

- **`submit` mode** (planned): after a VERIFIED result, open the registry submission
  automatically from CI — closing the loop from "signed in my repo" to "listed on skillx".
  Tracked in Linear.

## License

MIT © The Holding Company. See [LICENSE](./LICENSE).
