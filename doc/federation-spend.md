# Federation spend (Dilithium outputs)

This is the **wire**: output script bytes, witness stack, sizes, and
what the node accepts.

Dilithium outputs are **Bitcoin Script** in `scriptPubKey`. Kind is
`(algorithm, param)` looked up next to `OP_CHECKMODERNSIG` or
`OP_CHECKMODERNPOLICY`. It is not proven by sniffing witness sizes.
Native SegWit (BIP 141 P2WPKH, v0/20, secp256k1) stays a witness
program. Do not call Dilithium “SegWit.” P2WSH stays rejected.

C for 44/87 is the in-tree gitlinks `src/crypto/mldsa44` and
`src/crypto/mldsa87`. Not this layout.

Hex in this file and in the vector JSON is **stored-byte order**
(byte 0 first), the same as `HexStr`. It is **not** `uint256::GetHex()`,
which reverses bytes.

Committed vectors:
[src/test/data/federation_spend_vectors.json](../src/test/data/federation_spend_vectors.json).
Seeds plus PQClean ML-DSA keygen reproduce keys. The JSON also stores
one complete 44 and 87 single-key pubkey+signature.

The FIPS 204 context string is the raw ASCII bytes `FederationCoin`.

`scriptSig` must be empty. Extra witness items fail.

## Unified sighash preimage

Hasher is **SHA256**, BIP-340 `TaggedHash("UnifiedSighash")`, then
`GetSHA256()`. Not Blake2b (PoW `GetHash` and Dilithium fingerprints
are Blake2b; those are different objects). Epoch 0. Hashtype `0x21`
(`SIGHASH_ALL | SIGHASH_UNIFIED`). Version, then locktime plus a zero
byte. SHA256 single-hashes of prevouts, amounts, spent scripts, and
sequences. SHA256 of the outputs. `script_type` 1 (witness-unlocked).
Input index. **Empty `scriptCode`** for every product spend (secp
P2WPKH, Dilithium single, Dilithium policy). JSON vector hex is
stored-byte order (`ParseHex` then `uint256{span}`), not `GetHex`.

Consensus fee: a virtual byte is `floor(weight / 4)` (`ConsensusVsize`).
The floor is `floor(virtual_bytes / 12)`. BIP-141 ceil-vsize is not
this check.

## Opcodes and registry

Two new opcodes (genesis assignments, not NOP-as-soft-fork):

| Byte | Name | Stack shape |
| --- | --- | --- |
| `0xbb` | `OP_CHECKMODERNSIG` | single-key |
| `0xbc` | `OP_CHECKMODERNPOLICY` | policy (`t`, hashes, `n`) |

Script small ints are only `OP_1`…`OP_16`. **Do not push the integers
44 or 87.**

| Push | Slot | Meaning |
| --- | --- | --- |
| `OP_1` (`0x51`) | algorithm | `ALGO_DILITHIUM` |
| `OP_1` (`0x51`) | param | Dilithium 44 |
| `OP_2` (`0x52`) | param | Dilithium 87 |

The CHECK opcode pops param, then algorithm, and **looks up**
`(algorithm, param)` in a closed registry. Miss → fail (not
anyone-can-spend). Hit → a kind object that owns pubkey/sig sizes,
KEY tag, and verify. The opcode does not interpret “1 means 44.”

Genesis rows: `(OP_1, OP_1)` Dilithium-44, `(OP_1, OP_2)` Dilithium-87.
A later row is a hard fork. Unknown pairs fail.

## Envelope

Dilithium outputs are **not** BIP 141 witness programs
(`IsWitnessProgram` is false). The Script is in `scriptPubKey`.
Unlocking data is the **witness**. `scriptSig` is empty. That is not
P2WSH: the script is in the UTXO, not dumped at spend.

Native SegWit remains `OP_0` + a 20-byte HASH160 push (22 bytes).

`MAX_OUTPUT_SCRIPT_SIZE` (34) stays for non-templates. Modern-sig
templates admit up to `DILITHIUM_POLICY_SCRIPT_MAX` (401). Coinbase
witness commitment stays 38 bytes.

Address encoding is **bech32 of the locking-script bytes**. Not BIP
141 v0/32. Policy scripts are long. Do not P2WSH-wrap to shorten
them.

## Fingerprints

Blake2b-256 with a 32-byte output length. Preimage is one length byte
(ASCII length only), then those ASCII bytes, then the payload.

| Tag | ASCII length | Length byte |
| --- | --- | --- |
| `FCN-MLDSA44-KEY` | 15 | `0x0f` |
| `FCN-MLDSA87-KEY` | 15 | `0x0f` |

44 and 87 share tag *lengths*. The ASCII bytes differ. A 44 key cannot
satisfy an 87 output. Policy UTXOs push these **KEY** hashes; there is
no POLICY-tag fingerprint in the output.

## Four layouts (draft names)

| Label | Pubkey | Signature | Locking script |
| --- | --- | --- | --- |
| Dilithium-44 single | 1312 | 2420 | `<KEY fp> OP_1 OP_1 OP_CHECKMODERNSIG` |
| Dilithium-44 policy | 1312 | 2420 | `OP_t <KEY hash>*n OP_n OP_1 OP_1 OP_CHECKMODERNPOLICY` |
| Dilithium-87 single | 2592 | 4627 | `<KEY fp> OP_1 OP_2 OP_CHECKMODERNSIG` |
| Dilithium-87 policy | 2592 | 4627 | `OP_t <KEY hash>*n OP_n OP_1 OP_2 OP_CHECKMODERNPOLICY` |

Seed is 32 bytes. Max keys in a policy is 12. 32-byte pushes use the
minimal form (`0x20` then 32 bytes), not `OP_PUSHDATA1`. A single-key
locking script is **36 bytes** (`DILITHIUM_SINGLE_SCRIPT_SIZE`). An
unknown `(algorithm, param)` pair is not an address.

## Derivation

The ML-DSA seed is **not** a secp BIP32 child. A quantum break of an
exported account xpub must not yield Dilithium seeds.

Tagged KDF, Blake2b-256 with no key:

`Blake2b-256(tag || seed_material || kind_id || le32(index))`

| Field | Bytes |
| --- | --- |
| tag | ASCII `FederationCoin/ml-dsa-seed/v1` (no NUL) |
| seed_material (single-key) | wallet HD seed, or that descriptor's 32-byte root xprv secret |
| seed_material (policy) | that slot's 32-byte root xprv secret (never the wallet-wide HD seed) |
| kind_id | 1 = Dilithium 44, 2 = Dilithium 87, 3 = policy 44, 4 = policy 87 |
| index | little-endian uint32. Bits 0–30 are the wallet index (policy keys: `wallet_index * 12 + slot`). Bit 31 is set for the change chain so receive and change at the same index do not share a seed. |

One leaf must not serve every kind. FIPS 204 keygen then uses the
derived 32-byte seed with context `FederationCoin`.

Pinned vector (`mldsa_seed_tests.cpp`; same bytes in drongo): 32-byte
seed of `0x42`, kind Dilithium 87, index 7 →
`8d3755b302d8a066e6ae846b00e329cfd597043e812dc509b240876c171e8f68`.

Policy slots: two root xprv secrets (32× `0xa1` and 32× `0xb2`), kind
policy 44, receive indexes `0*12+0` and `0*12+1` → scriptPubKey
`51202b84379230309a0492bcb24fd24d52b1b81f89cfc4f821890770fd0e7cf335d920bf4fc5ead1b5876b86d9083d563608f8446e6f2b8288be542c2c99e213b66017525151bc`.

## Single-key spend

```text
scriptPubKey:  <32-byte KEY fingerprint>  OP_1  OP_1  OP_CHECKMODERNSIG
               <32-byte KEY fingerprint>  OP_1  OP_2  OP_CHECKMODERNSIG
witness:       <pubkey> <signature>
scriptSig:     empty
```

Witness is exactly two items: pubkey, then signature, of **this**
kind’s sizes. The CHECK pops param, algorithm, fingerprint, signature,
pubkey. Lookup must hit. Tagged KEY hash must equal the fingerprint.
The signature must verify. Extra items fail.

Example (seed `04` then 31 zero bytes, sighash `03` then 31 zero
bytes). KEY fingerprints:

- 44: `19248b64d108a2485a7d12db6a5513937427bd25be4679ec8586113a427e32f7`
- 87: `dd12777edadfa7eb456a32b2226bf1026cd2455b397f6a95a31ed8848e6f0af2`

Full pubkey and signature hex are in the JSON. `scriptPubKey` hex is
there too (`0x20` ‖ fingerprint ‖ `51` ‖ `51` or `52` ‖ `bb`).

## Policy create

- Key count `n` is 1 to 12.
- Threshold `t` is 1 to `n`.
- Inputs are the **tagged KEY hashes** (32 bytes each), not raw pubkeys.
- **Sort** those hashes with the same order as `uint256` `<` (memcmp of
  the **stored 32 bytes**). Do **not** sort by `GetHex()` / RPC hex.
- After sort, hashes must be **strictly increasing**. Equal hashes
  (duplicate keys) → no script. Unsorted `scriptPubKey` fails (do not
  sort for the spender).
- Emit `OP_t`, then each hash as a minimal 32-byte push, then `OP_n`,
  then `OP_1` (Dilithium), then `OP_1` or `OP_2` (44 or 87), then
  `OP_CHECKMODERNPOLICY`.
- **One kind only.** Every slot is Dilithium 87, or every slot is
  Dilithium 44. No mix. No native SegWit key in a Dilithium policy.

A wallet that concatenates hashes in `GetHex()` order without the
memcmp sort builds a different script. Vectors: `hex_display_sort` in
the JSON (`h_lo` < `h_hi` as bytes; `GetHex` sorts the other way).

## Policy spend

```text
scriptPubKey:  OP_t  <hash1> … <hashn>  OP_n  OP_1  OP_1|OP_2  OP_CHECKMODERNPOLICY
witness:       n items, same order as the hashes
scriptSig:     empty
```

- `OP_t` / `OP_n` are `OP_1`…`OP_12`.
- One witness item per slot: empty → skip; otherwise pubkey ‖
  signature of **this** kind’s sizes (one item; the kind splits on its
  widths).
- **`signed_ok == t`**. Extra filled slots fail (CHECKMULTISIG
  shape). Skip slots do not sign. `t` is on the output. Do not loop
  `t`.
- Slot `i`’s pubkey must KEY-hash to that slot’s hash. Extra items fail.

## 1-of-1 vs single-key

A one-key **policy** is `OP_1 <hash> OP_1 OP_1 OP_1 OP_CHECKMODERNPOLICY`.
A single-key is `<fingerprint> OP_1 OP_1 OP_CHECKMODERNSIG`. Different
scripts. No classifier.

For seed `04` then 31 zeros, 44, the KEY hash is
`19248b64d108a2485a7d12db6a5513937427bd25be4679ec8586113a427e32f7`
in both cases. The locking scripts still differ.

## Why P2WSH is rejected

P2WSH is BIP 141 “pay to SHA256 of a **script we run** from the
witness.” Policy scripts already live in the output. We reject P2WSH
because it is a **data disk**:

- The output is only 32 bytes. At spend you reveal the **full redeem
  script** as the last witness item. That script can be large. Witness
  is priced at 1/4 of base, so the file is cheap.
- Stack items before that script are arguments. They can be more
  pushes of payload. The script can `OP_DROP` them or end in `OP_TRUE`
  so it still “pays.”
- Many inputs in one tx, each with its own dump.

A P2WSH-shaped output (`OP_0` + 32 bytes that is not a secp v0/20) is
`EVAL_FALSE`. Extra witness items on a Dilithium spend fail.

## `OP_TRUE` / anyone-can-spend (not supported)

1. **P2WSH of `OP_TRUE`.** Rejected with the rest of P2WSH.
2. **Bare `OP_TRUE` in the output.** Not a modern-sig template. Spends
  fail (`EVAL_FALSE`). Creating a 1-byte `OP_TRUE` output still fits
  the 34-byte non-template cap, so it may sit in the UTXO set as a
  **brick** (unspendable). Not a street. Not a supported payment; do
  not use it.

If a street path is ever specified, it must not become a witness dump.
Do not implement a street from this document.

## Node dispatch (empty `scriptSig`)

- Modern-sig template (`OP_CHECKMODERNSIG` / `OP_CHECKMODERNPOLICY`
  with algo/param) → copy witness to the stack, execute the locking
  script, registry lookup, kind verify.
- v0/20 → secp P2WPKH checker (exact two witness items).
- anything else → `EVAL_FALSE`.

## Combining partial policy witnesses

`MergeMlDsa44Witnesses` and `MergeMlDsa87Witnesses` fill skip slots
from stacks that share the **same ordered hash list** as the output.
Different order or different `n` fails. A 32-byte sighash is required;
signed slots are verified. Mixed 44/87 stacks fail.
