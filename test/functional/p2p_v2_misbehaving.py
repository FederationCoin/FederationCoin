#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Encrypted P2P advertises V3 from genesis. Handshake-misbehavior cases stay
unit tests.
"""
from test_framework.messages import NODE_P2P_V2, NODE_P2P_V3
from test_framework.test_framework import BitcoinTestFramework


class EncryptedP2PMisbehaving(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-peertimeout=3"]]

    def run_test(self):
        network_info = self.nodes[0].getnetworkinfo()
        assert (int(network_info["localservices"], 16) & NODE_P2P_V2) == 0
        assert (int(network_info["localservices"], 16) & NODE_P2P_V3) == NODE_P2P_V3
        assert "P2P_V3" in network_info["localservicesnames"]
        assert "P2P_V2" not in network_info["localservicesnames"]
        self.log.info("NODE_P2P_V3 is on; handshake misbehavior is a unit test")


if __name__ == '__main__':
    EncryptedP2PMisbehaving(__file__).main()
