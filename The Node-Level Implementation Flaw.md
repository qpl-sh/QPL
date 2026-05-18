The Node-Level Implementation Flaw
An HSM (Hardware Security Module) is designed to ensure that cryptographic secrets never leave the physical hardware boundary. If an HSM is implemented correctly, the host machine requests a signature, and the HSM returns the signature without ever exposing the private key to the host's RAM.

If we examine the Pkcs11HsmProvider implementation in crates/qpl-crypto/src/hsm.rs, the developers left explicit documentation detailing a "Hybrid Architecture" workaround because current HSM firmware does not natively support ML-DSA and ML-KEM:

Crypto operations: PQC signing, verification, encapsulation, and decapsulation are performed in software using the pqcrypto crate.

To achieve this, the code performs the following steps during a signing operation:

It retrieves the encrypted private key material (the operator's shard) from the HSM.

It unwraps (decrypts) the key material directly into the host machine's RAM (let mut sk_bytes = self.unwrap_key_material(&wrapped)?;).

It performs the ML-DSA cryptographic signing operation in software using the host CPU.

It relies on the zeroize crate to wipe the memory afterward.

Why this is a High Vulnerability
Even though the material being extracted into RAM is "only a shard" and not the complete network key, it is the entirety of that specific operator's secret material.

Because the shard touches the host machine's memory in plaintext, it is vulnerable to RAM scraping, memory dumps, or kernel-level exploits on that specific node. If a sophisticated attacker compromises enough individual operator nodes (e.g., 3 out of 5 in a 3-of-5 quorum) and scrapes the RAM of each during signing operations, they can successfully steal enough shards to forge signatures or reconstruct the complete key.

Conclusion: The protocol's threshold design is robust and working as intended to prevent a single node compromise from ruining the network. However, the claim that the nodes are secured by an HSM is currently false in practice, as the software bypasses the hardware security boundary to perform the math in the host memory.

---

## Status: RESOLVED (May 2026) — via Algorithmic Agility

This finding has been resolved by introducing a cryptographic algorithmic agility layer in `crates/qpl-crypto/src/algorithm.rs` and `crates/qpl-crypto/src/hsm.rs`. Operators are no longer forced into the ML-DSA software-shim posture described above.

**What changed:**

The `HsmProvider` trait now exposes per-algorithm methods — `supported_signing_algorithms()`, `generate_signing_keypair(algorithm)`, `sign_agile(handle, msg)`, `verify_agile(...)`, and `export_public_key(handle)` — supporting three FIPS-validated algorithms:

| Algorithm | HSM Native? | Key Leaves HSM? |
|-----------|-------------|------------------|
| Ed25519 (RFC 8032 / FIPS 186-5) | Yes (universal on FIPS 140-3 hardware) | **No** |
| ECDSA-P256 (FIPS 186-4) | Yes (universal on FIPS 140-3 hardware) | **No** |
| ML-DSA-65 (FIPS 204) | Pending vendor firmware | Yes (transitional, software-only) |

**Production posture today:** Operators deploy on Ed25519 or ECDSA-P256 with FIPS 140-3 hardware (YubiHSM 2, AWS CloudHSM, Thales Luna, Entrust nShield). Key generation and signing both occur inside the HSM via PKCS#11 (`C_GenerateKeyPair`, `C_Sign`). The signing key never enters host RAM. RAM scraping, core dumps, and kernel-level exploits cannot extract a key that does not exist in host memory.

**Migration to ML-DSA-65:** As HSM vendors release FIPS 204 firmware, individual operators will add `MlDsa65` to their advertised capability set. The coordinator will negotiate ML-DSA-65 for any quorum where every participant supports it. No protocol upgrade, hard fork, or downtime is required.

**Threshold remains primary:** Even during the ML-DSA software-only window, the threshold property continues to provide the primary security boundary — fewer than `t` compromised shards reveal nothing about the aggregate signing key.

**References:**
- WHITEPAPER.md §3.6 (Cryptographic Algorithmic Agility)
- WHITEPAPER.md §10.5 (HSM Architecture and Side-Channel Resistance)
- PROTOCOL_FLOWS.md §3 (Algorithm negotiation flow)
- PROTOCOL_FLOWS.md §8 (HSM key lifecycle)
- Verified: 62 `qpl-crypto` unit tests passing, including Ed25519 / ECDSA-P256 sign-verify roundtrips and cross-algorithm signature rejection.