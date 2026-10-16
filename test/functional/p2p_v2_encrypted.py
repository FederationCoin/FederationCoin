#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Encrypted P2P is v3 from genesis. Python v1 peers still downgrade.
"""
from test_framework.messages import NODE_P2P_V2, NODE_P2P_V3
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class P2PEncrypted(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-v2transport=1"], ["-v2transport=1"]]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node0, node1 = self.nodes[0], self.nodes[1]
        for node in (node0, node1):
            network_info = node.getnetworkinfo()
            # MIN_FLEX receive still fits in a BIP324 v2 packet, so V2 stays
            # advertised until admit crosses MAX_CONTENTS_LEN. V3 is on from genesis.
            assert_equal(int(network_info["localservices"], 16) & NODE_P2P_V2, NODE_P2P_V2)
            assert_equal(int(network_info["localservices"], 16) & NODE_P2P_V3, NODE_P2P_V3)
            assert "P2P_V3" in network_info["localservicesnames"]

        self.log.info("Python v1 peers still downgrade")
        node0.add_p2p_connection(P2PInterface(), wait_for_verack=True, supports_v2_p2p=False)
        node0.add_p2p_connection(P2PInterface(), wait_for_verack=True, supports_v2_p2p=False)
        node0.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0, supports_v2_p2p=False, advertise_v2_p2p=False)
        node0.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1, supports_v2_p2p=False, advertise_v2_p2p=False)
        assert_equal(len(node0.getpeerinfo()), 4)
        for peer in node0.getpeerinfo():
            assert_equal(peer["transport_protocol_type"], "v1")
            assert_greater_than(peer['bytessent_per_msg']['version'], 0)
            assert_greater_than(peer['bytesrecv_per_msg']['verack'], 0)

        self.log.info("Two encrypted nodes speak v3")
        self.connect_nodes(0, 1)
        self.sync_all()
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        node_peers = [p for p in node0.getpeerinfo() if p["connection_type"] == "manual"]
        assert_equal(len(node_peers), 1)
        assert_equal(node_peers[0]["transport_protocol_type"], "v3")


if __name__ == '__main__':
    P2PEncrypted(__file__).main()
