# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""ML-DSA-44 and ML-DSA-87 keygen and sign for the test framework.

The bytes come from the same modules the node verifies. The context string
is FederationCoin.
"""

import hashlib
import os
import subprocess

from test_framework.script_util import fingerprint_to_modern_policy_script

# Stable seed so the premine address does not move between tests.
MINIWALLET_SEED = "11" * 32


def tool_path(node_binary, name="mldsa44-tool"):
    return os.path.join(os.path.dirname(os.path.abspath(node_binary)), name)


def keygen(node_binary, seed_hex=MINIWALLET_SEED):
    out = subprocess.check_output([tool_path(node_binary), "keygen", seed_hex], text=True, encoding="utf8").split()
    return {"pubkey": out[0], "secret": out[1], "program": out[2]}


def sign(node_binary, secret_hex, message):
    out = subprocess.check_output(
        [tool_path(node_binary), "sign", secret_hex, message.hex()],
        text=True,
        encoding="utf8",
    ).strip()
    return bytes.fromhex(out)


def keygen87(node_binary, seed_hex=MINIWALLET_SEED):
    out = subprocess.check_output([tool_path(node_binary, "mldsa87-tool"), "keygen", seed_hex], text=True, encoding="utf8").split()
    return {"pubkey": out[0], "secret": out[1], "program": out[2]}


def sign87(node_binary, secret_hex, message):
    out = subprocess.check_output(
        [tool_path(node_binary, "mldsa87-tool"), "sign", secret_hex, message.hex()],
        text=True,
        encoding="utf8",
    ).strip()
    return bytes.fromhex(out)


def key_hash(pubkey_hex):
    pubkey = bytes.fromhex(pubkey_hex)
    return hashlib.blake2b(bytes([0x0F]) + b"FCN-MLDSA44-KEY" + pubkey, digest_size=32).digest()


def key_hash87(pubkey_hex):
    pubkey = bytes.fromhex(pubkey_hex)
    return hashlib.blake2b(bytes([0x0F]) + b"FCN-MLDSA87-KEY" + pubkey, digest_size=32).digest()


def policy_program(threshold, hashes):
    return fingerprint_to_modern_policy_script(threshold, hashes, 1)


def policy_program87(threshold, hashes):
    return fingerprint_to_modern_policy_script(threshold, hashes, 2)


def sign_slots(node_binary, sighash, keys, signed_index):
    """Witness stack for a slots-only 44 policy. keys must already be hash-ordered."""
    stack = []
    for i, key in enumerate(keys):
        if i == signed_index:
            stack.append(bytes.fromhex(key["pubkey"]) + sign(node_binary, key["secret"], sighash))
        else:
            stack.append(b"")
    return stack


def sign_slots87(node_binary, sighash, keys, signed_index):
    """Witness stack for a slots-only 87 policy. keys must already be hash-ordered."""
    stack = []
    for i, key in enumerate(keys):
        if i == signed_index:
            stack.append(bytes.fromhex(key["pubkey"]) + sign87(node_binary, key["secret"], sighash))
        else:
            stack.append(b"")
    return stack
