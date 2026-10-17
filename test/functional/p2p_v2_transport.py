#!/usr/bin/env python3
# Copyright (c) 2021-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Node-to-node P2P is v3 from genesis.
"""
from test_framework.messages import NODE_P2P_V2, NODE_P2P_V3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)


class V3TransportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5

    def run_test(self):
        sending_handshake = "start sending v2 handshake to peer"
        for i in range(self.num_nodes):
            network_info = self.nodes[i].getnetworkinfo()
            assert_equal(int(network_info["localservices"], 16) & NODE_P2P_V2, 0)
            assert_equal(int(network_info["localservices"], 16) & NODE_P2P_V3, NODE_P2P_V3)
            assert "P2P_V3" in network_info["localservicesnames"]
            assert "P2P_V2" not in network_info["localservicesnames"]

        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)
        self.disconnect_nodes(2, 3)
        self.disconnect_nodes(3, 4)

        with self.nodes[0].assert_debug_log(expected_msgs=[sending_handshake]):
            self.connect_nodes(0, 1)
        self.generate(self.nodes[0], 5, sync_fun=lambda: self.sync_all(self.nodes[0:2]))
        assert_equal(self.nodes[1].getblockcount(), 5)
        for info in (self.nodes[0].getpeerinfo(), self.nodes[1].getpeerinfo()):
            assert_equal(len(info), 1)
            assert_equal(info[0]["transport_protocol_type"], "v3")
            assert_equal(len(info[0]["session_id"]), 64)

        self.connect_nodes(1, 2)
        self.connect_nodes(2, 3)
        self.connect_nodes(3, 4)
        self.generate(self.nodes[0], 3, sync_fun=self.sync_all)
        assert_equal(self.nodes[4].getblockcount(), 8)
        for i in range(self.num_nodes):
            for peer in self.nodes[i].getpeerinfo():
                assert_equal(peer["transport_protocol_type"], "v3")


if __name__ == '__main__':
    V3TransportTest(__file__).main()
