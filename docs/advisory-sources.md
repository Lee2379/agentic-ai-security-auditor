# Advisory Sources

The sample evidence models six dependency vulnerabilities observed in the operational audit. Each canonical finding consolidates a GHSA record and its corresponding PYSEC alias when both describe the same CVE.

| Package / observed version | Canonical advisory | Severity | Fixed version | Underlying issue |
|---|---|---:|---:|---|
| `aiohttp 3.14.1` | [GHSA-cq5v-8q36-5273](https://github.com/advisories/GHSA-cq5v-8q36-5273) | High | `3.14.3` | Out-of-bounds heap read in the C HTTP response parser error path |
| `aiohttp 3.14.1` | [GHSA-mfx4-hv73-q22v](https://github.com/advisories/GHSA-mfx4-hv73-q22v) | Moderate | `3.14.2` | HTTP request smuggling through WebSocket upgrade handling |
| `aiohttp 3.14.1` | [GHSA-mq44-7p77-q5h7](https://github.com/advisories/GHSA-mq44-7p77-q5h7) | Moderate | `3.14.2` | Compressed WebSocket frames accepted without negotiated compression |
| `cryptography 48.0.1` | [GHSA-g6cj-pr64-35w5](https://github.com/advisories/GHSA-g6cj-pr64-35w5) | High | `50.0.0` | PKCS#7 EnvelopedData decryption oracle |
| `cryptography 48.0.1` | [GHSA-jwv3-5hgf-82ww](https://github.com/advisories/GHSA-jwv3-5hgf-82ww) | High | `49.0.0` | Duplicate self-signed intermediates can cause exponential path building |
| `cryptography 48.0.1` | [GHSA-m2h6-j472-rp4c](https://github.com/advisories/GHSA-m2h6-j472-rp4c) | Moderate | `49.0.0` | Wildcard DNS names can escape permitted-subtree constraints |

## Interpretation rule

The table records affected package presence and upstream remediation guidance. It does **not** establish that Hermes executed the affected function or that the vulnerability was externally exploitable. Those questions remain Not Verified until feature-specific reachability, topology, and regression evidence is collected.

## Upgrade target

The report recommends `aiohttp >= 3.14.3` and `cryptography >= 50.0.0` because those versions cover all listed fixes for each package. Deployment must still pass compatibility, protocol, certificate-validation, and PKCS#7 regression tests before the findings can be closed.
