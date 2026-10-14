#!/usr/bin/env python3
# Copyright (c) 2021-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test v2 transport
"""
from test_framework.messages import NODE_P2P_V2, NODE_P2P_V3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
    assert_raises_rpc_error
)


class V2TransportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5
        self.extra_args = [["-v2transport=1"], ["-v2transport=1"], ["-v2transport=0"], ["-v2transport=0"], ["-v2transport=0"]]

    def run_test(self):
        sending_handshake = "start sending v2 handshake to peer"
        downgrading_to_v1 = "retrying with v1 transport protocol for peer"
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)
        self.disconnect_nodes(2, 3)
        self.disconnect_nodes(3, 4)

        # Encrypted P2P advertises V3 from genesis. The V2 bit drops when a
        # v2 packet cannot name a block (regtest window admit).
        for i in range(2):
            network_info = self.nodes[i].getnetworkinfo()
            assert_equal(int(network_info["localservices"], 16) & NODE_P2P_V2, 0)
            assert_equal(int(network_info["localservices"], 16) & NODE_P2P_V3, NODE_P2P_V3)
            assert "P2P_V2" not in network_info["localservicesnames"]
            assert "P2P_V3" in network_info["localservicesnames"]
        for i in range(2, self.num_nodes):
            network_info = self.nodes[i].getnetworkinfo()
            assert_equal(int(network_info["localservices"], 16) & NODE_P2P_V2, 0)
            assert_equal(int(network_info["localservices"], 16) & NODE_P2P_V3, 0)
            assert "P2P_V2" not in network_info["localservicesnames"]
            assert "P2P_V3" not in network_info["localservicesnames"]

        assert_equal(self.nodes[0].getblockcount(), 0)
        assert_equal(self.nodes[1].getblockcount(), 0)
        with self.nodes[0].assert_debug_log(expected_msgs=[sending_handshake]):
            self.connect_nodes(0, 1)
        self.generate(self.nodes[0], 5, sync_fun=lambda: self.sync_all(self.nodes[0:2]))
        assert_equal(self.nodes[1].getblockcount(), 5)
        node_0_info = self.nodes[0].getpeerinfo()
        node_1_info = self.nodes[1].getpeerinfo()
        assert_equal(len(node_0_info), 1)
        assert_equal(len(node_1_info), 1)
        assert_equal(node_0_info[0]["transport_protocol_type"], "v3")
        assert_equal(node_1_info[0]["transport_protocol_type"], "v3")
        assert_equal(len(node_0_info[0]["session_id"]), 64)
        assert_equal(len(node_1_info[0]["session_id"]), 64)

        # V1 nodes can sync with each other
        assert_equal(self.nodes[2].getblockcount(), 0)
        assert_equal(self.nodes[3].getblockcount(), 0)

        # addnode rpc error when v2transport requested but not enabled
        ip_port = "127.0.0.1:{}".format(p2p_port(3))
        assert_raises_rpc_error(-8, "Error: v2transport requested but not enabled (see -v2transport)", self.nodes[2].addnode, node=ip_port, command='add', v2transport=True)

        with self.nodes[2].assert_debug_log(expected_msgs=[],
                                            unexpected_msgs=[sending_handshake, downgrading_to_v1]):
            self.connect_nodes(2, 3, peer_advertises_v2=False)
        self.generate(self.nodes[2], 8, sync_fun=lambda: self.sync_all(self.nodes[2:4]))
        assert_equal(self.nodes[3].getblockcount(), 8)
        assert self.nodes[0].getbestblockhash() != self.nodes[2].getbestblockhash()
        # verify there is a v1 connection between node 2 and 3
        node_2_info = self.nodes[2].getpeerinfo()
        node_3_info = self.nodes[3].getpeerinfo()
        assert_equal(len(node_2_info), 1)
        assert_equal(len(node_3_info), 1)
        assert_equal(node_2_info[0]["transport_protocol_type"], "v1")
        assert_equal(node_3_info[0]["transport_protocol_type"], "v1")
        assert_equal(len(node_2_info[0]["session_id"]), 0)
        assert_equal(len(node_3_info[0]["session_id"]), 0)

        # V1 nodes can sync with V2 nodes
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(2, 3)
        with self.nodes[2].assert_debug_log(expected_msgs=[],
                                            unexpected_msgs=[sending_handshake, downgrading_to_v1]):
            self.connect_nodes(2, 1, peer_advertises_v2=False) # cannot enable v2 on v1 node
        self.sync_all(self.nodes[1:3])
        assert_equal(self.nodes[1].getblockcount(), 8)
        assert self.nodes[0].getbestblockhash() != self.nodes[1].getbestblockhash()
        # verify there is a v1 connection between node 1 and 2
        node_1_info = self.nodes[1].getpeerinfo()
        node_2_info = self.nodes[2].getpeerinfo()
        assert_equal(len(node_1_info), 1)
        assert_equal(len(node_2_info), 1)
        assert_equal(node_1_info[0]["transport_protocol_type"], "v1")
        assert_equal(node_2_info[0]["transport_protocol_type"], "v1")
        assert_equal(len(node_1_info[0]["session_id"]), 0)
        assert_equal(len(node_2_info[0]["session_id"]), 0)

        # V2 nodes can sync with V1 nodes
        self.disconnect_nodes(1, 2)
        with self.nodes[0].assert_debug_log(expected_msgs=[],
                                            unexpected_msgs=[sending_handshake, downgrading_to_v1]):
            self.connect_nodes(0, 3, peer_advertises_v2=False)
        self.sync_all([self.nodes[0], self.nodes[3]])
        assert_equal(self.nodes[0].getblockcount(), 8)
        # verify there is a v1 connection between node 0 and 3
        node_0_info = self.nodes[0].getpeerinfo()
        node_3_info = self.nodes[3].getpeerinfo()
        assert_equal(len(node_0_info), 1)
        assert_equal(len(node_3_info), 1)
        assert_equal(node_0_info[0]["transport_protocol_type"], "v1")
        assert_equal(node_3_info[0]["transport_protocol_type"], "v1")
        assert_equal(len(node_0_info[0]["session_id"]), 0)
        assert_equal(len(node_3_info[0]["session_id"]), 0)

        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2, peer_advertises_v2=False)
        self.generate(self.nodes[1], 1, sync_fun=lambda: self.sync_all(self.nodes[0:4]))
        assert_equal(self.nodes[0].getblockcount(), 9)

        self.generate(self.nodes[3], 2, sync_fun=lambda: self.sync_all(self.nodes[0:4]))
        assert_equal(self.nodes[2].getblockcount(), 11)

        assert_equal(self.nodes[4].getblockcount(), 0)
        with self.nodes[1].assert_debug_log(expected_msgs=[],
                                            unexpected_msgs=[sending_handshake, downgrading_to_v1]):
            self.connect_nodes(1, 4, peer_advertises_v2=False)
        self.sync_all()
        assert_equal(self.nodes[4].getblockcount(), 11)


if __name__ == '__main__':
    V2TransportTest(__file__).main()
