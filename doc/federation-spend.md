# Federation spend (Dilithium outputs)

This is the **wire**: output script bytes, witness stack, sizes, and
what the node accepts. [Epic 21](../../docs/epics/21-quantum-flexibility.md)
is the product story. Draft labels until named. Dummy MAIN unlaunched.

Not a BIP 141 upgrade. P2WPKH and P2WSH are BIP 141 names. Our v0/32
Dilithium single-key and policy spends use the BIP 141 **envelope**
(`OP_0` + 32-byte fingerprint) and are **not** P2WSH. Do not call
Dilithium “SegWit.” The kind named SegWit is native P2WPKH (v0/20,
secp256k1). Those checkers are specified with the rest of the SegWit
cleanup, not here.

C we call for 44/87, and CC0/public-domain terms:
[mldsa-libraries.md](../../docs/mldsa-libraries.md). Not this layout.

Hex in this file and in the vector JSON is **stored-byte order**
(byte 0 first), the same as `HexStr`. It is **not** `uint256::GetHex()`,
which reverses bytes.

Committed vectors:
[src/test/data/federation_spend_vectors.json](../src/test/data/federation_spend_vectors.json).
Seeds plus PQClean ML-DSA keygen reproduce keys. The JSON also stores
one complete 44 and 87 single-key pubkey+signature.

The FIPS 204 context string is the raw ASCII bytes `FederationCoin`.

`scriptSig` must be empty. Extra witness items fail.

## Unified sighash preimage (product v0)

Hasher is **SHA256**, BIP-340 `TaggedHash("UnifiedSighash")`, then
`GetSHA256()`. Not Blake2b (PoW `GetHash` and Dilithium fingerprints
are Blake2b; those are different objects). Epoch 0. Hashtype `0x21`
(`SIGHASH_ALL | SIGHASH_UNIFIED`). Version, then locktime plus a zero
byte. SHA256 single-hashes of prevouts, amounts, spent scripts, and
sequences. SHA256 of the outputs. `script_type` 1 for `WITNESS_V0`.
Input index. **Empty `scriptCode`** for every product v0 spend (secp
P2WPKH, Dilithium 44/87 single, Dilithium t-of-n). JSON vector hex is
stored-byte order (`ParseHex` then `uint256{span}`), not `GetHex`.

Consensus fee: a virtual byte is `floor(weight / 4)` (`ConsensusVsize`).
The floor is `floor(virtual_bytes / 12)`. BIP-141 ceil-vsize is not
this check.

## Envelope

Every Dilithium output is witness version 0, 32-byte program:

- scriptPubKey: `OP_0` + a 32-byte push (34 bytes).
- The 32 bytes are a **fingerprint**, not a script the node runs.

Single-key and policy use that **same envelope**. Kind is proven at
spend: the node tries 44/87 single and policy checkers. Native SegWit
(v0/20) is a different envelope.

## Fingerprints

Blake2b-256 with a 32-byte output length. Preimage is one length byte
(ASCII length only), then those ASCII bytes, then the payload.

| Tag | ASCII length | Length byte |
| --- | --- | --- |
| `FCN-MLDSA44-KEY` | 15 | `0x0f` |
| `FCN-MLDSA44-POLICY` | 18 | `0x12` |
| `FCN-MLDSA87-KEY` | 15 | `0x0f` |
| `FCN-MLDSA87-POLICY` | 18 | `0x12` |

44 and 87 share tag *lengths*. The ASCII bytes differ. A 44 key cannot
satisfy an 87 address.

## Four layouts (draft names)

| Label | Pubkey | Signature | Program |
| --- | --- | --- | --- |
| Dilithium-44 single | 1312 | 2420 | KEY tag + pubkey |
| Dilithium-44 policy | 1312 | 2420 | POLICY tag + `t` + `n` + sorted hashes |
| Dilithium-87 single | 2592 | 4627 | KEY tag + pubkey |
| Dilithium-87 policy | 2592 | 4627 | POLICY tag + `t` + `n` + sorted hashes |

Seed is 32 bytes. Max keys in a policy is 12.

### Single-key spend

Witness is exactly two items: pubkey, then signature, of **this**
kind’s sizes. The pubkey’s tagged KEY hash must equal the 32-byte
program. The signature must verify. Extra items fail.

Example (seed `04` then 31 zero bytes, sighash `03` then 31 zero
bytes). Programs:

- 44 single: `19248b64d108a2485a7d12db6a5513937427bd25be4679ec8586113a427e32f7`
- 87 single: `dd12777edadfa7eb456a32b2226bf1026cd2455b397f6a95a31ed8848e6f0af2`

Full pubkey and signature hex are in the JSON.

### Policy create

- Key count `n` is 1 to 12.
- Threshold `t` is 1 to `n`.
- Inputs are the **tagged key hashes** (32 bytes each), not raw pubkeys.
- **Sort** those hashes with the same order as `uint256` `<` (memcmp of
  the **stored 32 bytes**). Do **not** sort by `GetHex()` / RPC hex.
- After sort, hashes must be **strictly increasing**. Equal hashes
  (duplicate keys) → no program. Unordered input is sorted; duplicates
  still fail.
- Preimage: 1-byte length `0x12`, ASCII policy tag, then `t`, then `n`,
  then the **sorted** hashes concatenated. Blake2b-256 → 32-byte
  program. Envelope is still `OP_0` + those 32 bytes.
- **One kind only.** Every slot is Dilithium 87, or every slot is
  Dilithium 44. No mix. No native SegWit key in a Dilithium policy.

A wallet that concatenates hashes in `GetHex()` order without the
memcmp sort builds a different program. Vectors:
`hex_display_sort` in the JSON (`h_lo` < `h_hi` as bytes; `GetHex`
sorts the other way).

### Policy spend

- Witness is **n slots** in that **same sorted order**. Reordering is
  invalid even if the set of keys is the same.
- Each slot is skip (32-byte hash) or signed (pubkey + sig of **this**
  kind). Whole stack consumed. Extra items fail.
- **`signed_ok >= t`**. Skip slots do not sign.
- **`t` is not in the output.** Only the 32-byte program. The checker
  tries `t = 1 … n` until `PolicyProgram(t, hashes)` equals the
  program, then applies `signed_ok >= t`.
- Strictly increasing is checked **again** on the hashes taken from
  the witness. Fail on equal or descending.

Skip hashes are **32 untyped bytes** to consensus. Consensus cannot
see whether that hash came from a 44 key or an 87 key. Wallets still
must hash **this policy’s kind**. A skip hash of the other kind can
never become a signed slot on this checker (signed needs this kind’s
pubkey size). Do not build mixed policies. A 44 pubkey in an 87 walk
is the wrong item size. A 44 program will not match an 87 checker.

### 1-of-1 vs single-key

A one-key **policy** is allowed (`n >= 1`). Its program is **not** the
single-key fingerprint (different tag and `t`,`n` in the preimage).

For seed `04` then 31 zeros, 44:

- single program: `19248b64d108a2485a7d12db6a5513937427bd25be4679ec8586113a427e32f7`
- 1-of-1 policy: `5b9e869db856a8165cba063d8b10f7c7df07d0f99504b46922b9ffcb7987d83c`

A two-item `[pubkey, sig]` stack is the **single-key shape** and also a
**one-slot signed policy shape**. The layout classifier tests single
shape first. Validity is still `CheckSingleKey*` vs `CheckMultisig*`
against the **program**.

## Layout vs validity

The classifier answers **shape**: `Single`, `Policy`, or `Neither`.
It does not decide whether the spend is valid. A `Policy` layout can
still fail the policy checker.

## Why P2WSH is rejected

P2WSH is BIP 141 “pay to SHA256 of a **script we run** from the
witness.” We do not need it for multisig (policy fingerprints do
that). We reject it because it is a **data disk**:

- The output is only 32 bytes. At spend you reveal the **full redeem
  script** as the last witness item. That script can be large. Witness
  is priced at 1/4 of base, so the file is cheap.
- Stack items before that script are arguments. They can be more
  pushes of payload. The script can `OP_DROP` them or end in `OP_TRUE`
  so it still “pays.”
- Many inputs in one tx, each with its own dump.
- That is not a payment condition. It is a file with a hash in the
  UTXO.

Federation v0/32 does **not** run a redeem script. Extra items fail.
That is the spec, not a later tightening. A P2WSH-shaped witness
(redeem script last) is `Neither` and `EVAL_FALSE`.

## `OP_TRUE` / anyone-can-spend (not supported)

1. **P2WSH of `OP_TRUE`.** Rejected with the rest of P2WSH.
2. **Bare `OP_TRUE` in the output.** Not a witness program. The node
  does not execute output Script. Spends fail (`EVAL_FALSE`). Creating
  a 1-byte `OP_TRUE` output still fits the 34-byte output cap, so it
  may sit in the UTXO set as a **brick** (unspendable). Not a street.
  Not a supported payment; do not use it.

If a street path is ever specified, it must not become a witness dump.
Do not implement a street from this document.

## Node dispatch (empty `scriptSig`)

- v0/20 → secp P2WPKH checker (exact two witness items).
- v0/32 → Dilithium 44/87 single or policy checkers.
- anything else → `EVAL_FALSE`.

## Combining partial policy witnesses

`MergeMlDsa44Witnesses` and `MergeMlDsa87Witnesses` fill skip slots
from stacks that share the **same ordered hash list**. Different order
or different `n` fails. A 32-byte sighash is required; signed slots
are verified. Mixed 44/87 stacks fail.
