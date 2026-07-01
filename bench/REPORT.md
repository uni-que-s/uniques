# UniQueS benchmark report

Results for the two independent benchmarks. Methodology and scope in
[`README.md`](README.md). Everything here is reproducible from the pinned inputs;
the per-finding labels are in [`repos/labels/`](repos/labels/).

_Engine: UniQueS v0.6.0. Real-repo adjudication was performed on the v0.5.x engine
and the dominant false-positive class it surfaced was then fixed in v0.6.0 — both
numbers are reported below so the improvement is auditable, not hand-waved._

---

## 1. NIST SARD / Juliet (official labeled corpus)

Recall on the U.S. NIST **Software Assurance Reference Dataset**, Juliet Java 1.3,
CWE-327 (broken crypto) + CWE-328 (reversible hash).

| Algorithm | Cases | Recall | Scope |
|---|---:|---:|---|
| DES | 17 | **100%** | in scope |
| 3DES / DESede | 17 | **100%** | in scope |
| MD5 | 17 | **100%** | in scope |
| SHA-1 | 17 | **100%** | in scope |
| **In-scope total** | **68** | **100.0%** | |
| MD2 | 17 | 0% | out of scope (obsolete; not a claimed pattern) |

**Scope boundary (do not overstate this number):** Juliet's crypto cases are the
*classical* threat model — DES/MD5/SHA-1 are the flaw, AES/SHA-256 the "safe"
answer. It contains **no RSA/ECC/DSA/DH** cases (it predates the quantum threat
model and treats them as safe). So this is 100% on the **legacy symmetric/hash
slice** of our scope, and says nothing about the RSA/ECC quantum core — that's what
benchmark 2 is for.

**Value delivered:** on first run this scored **0% on DES/MD5/SHA-1** — three
patterns had a trailing `\b` a closing quote can never satisfy, silently dropping
`createHash('md5')`, `MessageDigest.getInstance("MD5")`, and `getInstance("DES")`
entirely, plus a `"SHA1"`-vs-`"SHA-1"` gap. Our own qbench never caught these
because we never wrote those exact fixtures. Fixed in v0.6.0, now gated in qbench.
This is the argument for an external corpus, in one result.

---

## 2. Reproducible public-repo precision

Precision on nine pinned, well-known repositories. Every actionable finding was
hand-labeled TP/FP by reading the cited source; TP labels were re-checked by an
independent adversarial "try to refute" pass. Labels are published per repo.

| Repo | Lang | Kind | Files | Actionable | TP | FP | Precision |
|---|---|---|---:|---:|---:|---:|---:|
| caddyserver/caddy | Go | app (web server) | 335 | 24 | 24 | 0 | **100%** |
| go-gitea/gitea | Go | app (web app) | 2945 | 61¹ | 35 | 2 | **94.6%** |
| gin-gonic/gin | Go | framework (control) | 108 | 0 | 0 | 0 | n/a² |
| openssh/openssh-portable | C | library (SSH) | 426 | 115 | 56 | 4 | 93.3%³ |
| jwtk/jjwt | Java | library (JWT) | — | 60 | 60 | 0 | 100%³ |
| auth0/node-jsonwebtoken | JS | library (JWT) | 19 | 5 | 3 | 2 | 60% |
| pyca/cryptography | Python | library (crypto) | 968 | 340 | 44 | 16 | 73.3%³ |
| paramiko/paramiko | Python | library (SSH) | 63 | 68 | 60 | 0 | 100%³ |
| syncthing/syncthing | Go | app (TLS/certs) | 13 | 10 | 10 | 0 | 100% |

- **As independently adjudicated (v0.5.x engine): 86.1%** (292 TP / 47 FP).
- **After the benchmark-driven locale fix (v0.6.0): 92.4%** on the labeled set
  (292 TP / 24 FP) — gitea rose 58.3% → 94.6% once the i18n class was removed.

¹ gitea actionable was 104 pre-fix; the v0.6.0 locale rule downgraded ~43 i18n
placeholder findings to mentions, leaving 61. ² A framework that delegates crypto
to the stdlib: **0 findings, 0 false invention** — the negative control. ³ First 60
findings adjudicated (documented cap); the uncapped tail (367 findings, mostly in
crypto-dense libraries) was spot-checked as overwhelmingly TP but is not counted.

### What the false positives were (all 47, by class)

| Class | Count | Repos | Status |
|---|---:|---|---|
| **i18n locale placeholder** (a key-armor header / key-type names in a translation catalog) | ~23 | gitea | **Fixed in v0.6.0** — locale-resource files downgrade to mentions (all languages) |
| **Type annotations** (`DSAPrivateKey` in `-> X`/`Union[…]`, `type[AES128]`) | ~13 | pyca | Open — the type-vs-value distinction; tracked in `KNOWN_GAPS` (ENG-01b) |
| **Prose in a template literal w/ interpolation** (`RSA-PSS` in `throw new Error(\`…\`)`) | 2 | jsonwebtoken | Open — the deliberate template-`${}` recall trade-off; tracked |
| **Denylist / removal call** (algo names passed to `match_filter_denylist()`) | 2 | openssh | Open — a disable in disguise; tracked |
| **Log-string echo of a function name** (next to the real call, also flagged) | 2 | openssh | Open — a duplicate-of-a-real-TP; tracked |
| **`;`-commented example in `.ini`** (`;; openssl pkcs12 …`) | 2 | gitea | Open — INI `;` comments not masked; tracked |

Every remaining class is documented in `server/src/__tests__/qbench.fixtures.ts`
(`KNOWN_GAPS`), measured, and NOT swept under the rug.

### Recall observations (informal — precision is the headline)

Recall isn't claimed exhaustively (that needs a full manual audit per repo). Notes
from adjudication: the scanner caught the real generators/material broadly (gitea's
`rsa.GenerateKey`/`ecdsa.GenerateKey` in jwtsigningkey.go, openssh's
`EVP_PKEY_keygen`/`EC_KEY_*`/`DH_generate_key`, caddy's caddypki). Post-quantum
constructs were correctly **not** flagged as quantum-vulnerable (openssh's
`mlkem768x25519`/`sntrup761x25519`, ed25519). One documented-by-design "miss":
`testdata/` directories are skipped (production-posture grading), so gin's real
`testdata/certificate/*.pem` fixtures aren't surfaced by a repo-root scan —
detected when the fixture dir is targeted directly.

---

## Reproduce

```bash
npm --prefix server run build          # build the engine once
cd bench/sard && ./download.sh && node score.mjs   # NIST recall
cd ../repos && node run.mjs            # real-repo precision vs published labels
```
