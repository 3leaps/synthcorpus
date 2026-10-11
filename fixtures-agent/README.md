# fixtures-agent/ — GnuPG agent key specimens (committed-synthetic)

Every file here is **synthetic by construction**. Key parameters are
placeholders (`#00#`, `x`), so no file is usable as a key.
`internal/provability` proves this (`TestAgentKeyParametersArePlaceholders`)
and reconciles the inventory against the verdict manifest
(`TestAgentKeyInventoryMatchesManifest`).

Expected detector verdicts live in `manifests/decernor-scan-verdicts.json`.
Each entry gives the fixture's class, the placement a consumer must stage it
at before scanning, the expected finding per profile, and the expected
`guardread` verdict. Expectations follow the GnuPG agent key format
(`doc/keyformat.txt`) and each fixture's intended class. They are not derived
from any detector's output.

| Class | Directory | Intent |
| ----- | --------- | ------ |
| plaintext | `plaintext/` | Unprotected key in every encoding and layout the format allows |
| protected | `protected/` | Passphrase-protected key |
| hardware-stub | `stub/` | Smartcard or TPM shadow stub; holds no private key |
| malformed | `malformed/` | Ambiguous or invalid agent key content that must fail closed |
| benign | `benign/` | Non-key content that mentions agent key tokens |
| keyring-internal | `keyring/` | GnuPG home files, by name, with and without key content |

This directory sits outside `fixtures/` so the existing fingerprint golden is
unchanged. Changing a file means updating its manifest digest deliberately.

## Manifest semantics (v0)

- **Profiles:** every severity map names exactly `artifact` and `workstation`.
- **Expectations:** `expect` is the primary expected finding, or `null` for no
  primary expectation. `also_expect` lists further expected findings and is
  additive. When `expect` is `null` and `also_expect` is empty, the specimen
  must produce **no** findings. Otherwise the specimen must produce exactly the
  listed findings, one per entry, and no others.
- **Vocabulary:** `placements`, classes, and `invariant_rules` are closed sets
  owned by this repository and versioned with the manifest. A consumer rejects
  values it does not support. Changing a rule's meaning requires a new rule ID
  or a new contract version, followed by consumer review and a pin bump.
- **Boundary:** a consumer's check that its rule names match this manifest
  proves name parity only. That a rule's implementation matches its stated
  meaning is shown by the consumer's own negative controls.
