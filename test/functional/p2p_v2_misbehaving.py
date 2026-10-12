#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Regtest window admit does not fit BIP324, so the node never starts a v2
handshake. Handshake-misbehavior cases are unit tests under MIN_FLEX.
"""
from test_framework.messages import NODE_P2P_V2
from test_framework.test_framework import BitcoinTestFramework


class EncryptedP2PMisbehaving(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-v2transport=1", "-peertimeout=3"]]

    def run_test(self):
        network_info = self.nodes[0].getnetworkinfo()
        assert (int(network_info["localservices"], 16) & NODE_P2P_V2) == 0
        assert "P2P_V2" not in network_info["localservicesnames"]
        self.log.info("NODE_P2P_V2 is off; v2 handshake misbehavior is a unit test")


if __name__ == '__main__':
    EncryptedP2PMisbehaving(__file__).main()
