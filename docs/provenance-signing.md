# Signing Capa provenance attestations: L1 to L2

Capa emits a **SLSA Build L1** provenance attestation
([`capa --provenance`](../README.md)): an in-toto Statement v1
envelope carrying a SLSA Provenance v1.0 predicate, with the
source SHA-256 as the subject. L1 is "provenance generated and
distributed".

**SLSA Build L2** adds signed provenance and a hosted, tamper-
resistant build platform. Capa stays independent of any
specific signing service so the language is not coupled to
Sigstore, AWS KMS, or a particular CA. Signing is documented as
an external step. This page walks the end-to-end workflow.

> Companion script:
> [`deploy/sign-provenance.sh`](../deploy/sign-provenance.sh).
> Run it on any `.capa` file to produce a signed attestation.

---

## The two-stage workflow

```
   .capa source                      .capa.provenance.json
        |                                    |
        v                                    v
   capa --provenance  -->  in-toto + SLSA   --> cosign sign-blob  -->  .sig
                            (unsigned L1)              ^
                                                       |
                                                key material
                                          (private keypair OR Sigstore OIDC)
```

Stage 1 is part of the Capa compiler. Stage 2 is cosign or any
other in-toto-compatible signer.

---

## Stage 1: emit the L1 attestation

```bash
capa --provenance examples/hello.capa > hello.capa.provenance.json
```

The output is a single JSON document:

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [
    {
      "name": "hello.capa",
      "digest": { "sha256": "01c653151fec3def..." }
    }
  ],
  "predicate": {
    "buildDefinition": {
      "buildType": "https://capa-lang.org/build/transpile-to-python/v1",
      "externalParameters": { "source": "hello.capa" },
      "internalParameters": {
        "capaVersion": "0.7.0",
        "target": "python>=3.10"
      },
      "resolvedDependencies": []
    },
    "runDetails": {
      "builder": {
        "id": "https://capa-lang.org/cli",
        "version": { "capa": "0.7.0" }
      },
      "metadata": {
        "invocationId": "...",
        "startedOn": "...",
        "finishedOn": "..."
      },
      "byproducts": []
    }
  }
}
```

The `invocationId` is deterministic for a given source content
and filename, so reproducible builds get matching attestations.

---

## Stage 2: sign with cosign

Three signing modes are commonly used; pick the one that fits
your environment.

### Mode A: keypair-based (offline / private)

The simplest mode. Generate a long-lived keypair, store the
private half in a secret, distribute the public half alongside
the attestation.

```bash
# One-off: generate a keypair (interactive password prompt).
cosign generate-key-pair

# Sign:
cosign sign-blob \
    --key cosign.key \
    --output-signature hello.capa.provenance.json.sig \
    --yes \
    hello.capa.provenance.json

# Verify (anyone with cosign.pub can do this):
cosign verify-blob \
    --key cosign.pub \
    --signature hello.capa.provenance.json.sig \
    hello.capa.provenance.json
```

Pros: works offline, no third-party dependencies, no log
entries. Cons: key management is the manufacturer's problem;
key loss means resigning every artefact.

### Mode B: Sigstore keyless (public-chain)

Sigstore's keyless flow uses short-lived certificates issued
through OIDC, anchored in a transparency log (Rekor). No
long-lived private key needs to be stored.

```bash
# Sign. Opens a browser for OIDC auth, then issues a short-
# lived certificate.
cosign sign-blob \
    --output-signature hello.capa.provenance.json.sig \
    --output-certificate hello.capa.provenance.json.cert \
    --yes \
    hello.capa.provenance.json

# Verify. The certificate identity must match the OIDC subject
# that signed.
cosign verify-blob \
    --signature hello.capa.provenance.json.sig \
    --certificate hello.capa.provenance.json.cert \
    --certificate-identity you@example.com \
    --certificate-oidc-issuer https://accounts.google.com \
    hello.capa.provenance.json
```

Pros: no long-lived keys, transparency log gives auditability.
Cons: requires online OIDC + Rekor; some organisations cannot
publish to the public log.

### Mode C: hosted build platform (true SLSA L2)

For SLSA L2 in the formal sense, the build itself must run on
a hosted, tamper-resistant platform (GitHub Actions with the
`slsa-framework/slsa-github-generator`, GitLab CI, or
equivalent). The platform emits the attestation; Capa is one
step inside that pipeline.

A minimal GitHub Actions workflow:

```yaml
# .github/workflows/release.yml
name: Release with SLSA L2 provenance
on:
  push:
    tags: ['v*']

permissions:
  contents: write
  id-token: write       # required for keyless signing
  attestations: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e .
      - name: Emit Capa provenance
        run: |
          capa --provenance examples/hello.capa \
            > artefacts/hello.capa.provenance.json
      - name: Attest artefact with GitHub OIDC + Sigstore
        uses: actions/attest-build-provenance@v1
        with:
          subject-path: artefacts/hello.capa
```

The `attest-build-provenance` action publishes a signed
attestation to Rekor and produces a verifiable Sigstore bundle.
The build runs on GitHub's hosted runners, which is what makes
the L2 claim defensible (the manufacturer's developer machine
does not.

---

## Verification

Whoever receives the attestation can independently verify it:

```bash
# Mode A:
cosign verify-blob --key cosign.pub \
    --signature hello.capa.provenance.json.sig \
    hello.capa.provenance.json

# Mode B:
cosign verify-blob \
    --signature hello.capa.provenance.json.sig \
    --certificate hello.capa.provenance.json.cert \
    --certificate-identity ... --certificate-oidc-issuer ... \
    hello.capa.provenance.json

# Sigstore bundle (Mode C):
slsa-verifier verify-artifact \
    --provenance-path attestation.bundle \
    --source-uri github.com/nelsonduarte/capa \
    --builder-id "https://github.com/actions/runner/" \
    hello.capa
```

A verifier that recovers the source SHA-256 from the
attestation, then computes the SHA-256 of the .capa source
locally, and compares the two, knows the artefact came from
exactly that source through the declared build process.

---

## What this gets you under each framework

- **CRA Annex I Part I (2)(f)** (integrity of data and
  programs): signed provenance is the standard evidence that
  the SBOM and the source were not tampered with after
  building.
- **NIS2 Article 21(2)(d)** (supply chain security): a
  supplier shipping signed provenance allows the operator to
  verify the binary came from the declared source.
- **DORA Articles 28-30** (ICT third-party risk): same
  argument, financial-sector specific.
- **NIST SSDF PS.4** (build artefacts from source): the
  attestation is the direct evidence.
- **OWASP SCVS Domain 6** (Pedigree and Provenance): L1
  satisfies baseline, signed provenance lifts toward L2 and
  L3 of SCVS depending on the signing infrastructure.

For the broader regulatory mapping see
[`docs/regulatory.md`](regulatory.md).

---

## What this does *not* claim

- **L2 is more than signing.** True SLSA L2 requires the
  build to run on a hosted platform; the signing alone does
  not lift L1 to L2 in the formal sense. The "Mode A" workflow
  above produces a signed L1 attestation, which is informally
  closer to L1+ than to L2.
- **Long-lived keypairs need rotation.** Mode A is the
  simplest workflow but the least defensible operationally;
  organisations should plan key rotation and revocation.
- **Capa does not verify signatures.** Verification is a
  cosign / slsa-verifier operation. Capa emits the
  attestation; consumers verify with the tool of their choice.
