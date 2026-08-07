# Vendored verifier provenance

`skillx.py` in this repo is a pinned copy of the canonical skillx verifier so that
Action runs are reproducible and auditable — the Action never downloads a verifier at
runtime.

| Field  | Value |
| ------ | ----- |
| Source | <https://skillx.md/skillx.py> (canonical CLI; source: `The-Holding-Company/skillx`) |
| SHA-256 | `140caf1a12a87e5a386944b768efa3d5054172924777555e6d066ee5d87e6542` |
| Vendored | 2026-07-26 |

To refresh: replace `skillx.py`, update the SHA-256 above
(`shasum -a 256 skillx.py`), and cut a new release tag.
