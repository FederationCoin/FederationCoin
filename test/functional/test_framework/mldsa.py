# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""ML-DSA-44 keygen and sign for the test framework.

The bytes come from the same module the node verifies. The context string
is FederationCoin.
"""

import os
import subprocess

# Stable seed so the premine address does not move between tests.
MINIWALLET_SEED = "11" * 32


def tool_path(node_binary):
    return os.path.join(os.path.dirname(os.path.abspath(node_binary)), "mldsa44-tool")


def keygen(node_binary, seed_hex=MINIWALLET_SEED):
    out = subprocess.check_output([tool_path(node_binary), "keygen", seed_hex], text=True).split()
    return {"pubkey": out[0], "secret": out[1], "program": out[2]}


def sign(node_binary, secret_hex, message):
    out = subprocess.check_output(
        [tool_path(node_binary), "sign", secret_hex, message.hex()],
        text=True,
    ).strip()
    return bytes.fromhex(out)
