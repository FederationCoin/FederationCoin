#!/usr/bin/env python3
# Copyright (c) 2026 The FederationCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""v1 and v2 transports are rejected. There is no -v2transport option."""
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
)


class P2PV3Rejected(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Inbound v1 is disconnected")
        v1 = P2PInterface()
        node.add_p2p_connection(v1, supports_v2_p2p=False, expect_success=False, wait_for_verack=False)
        v1.wait_for_disconnect()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        self.log.info("Empty BIP324 version packet still speaks v3")
        empty = P2PInterface()
        empty.encrypted_version = b''
        node.add_p2p_connection(empty)

        self.log.info("v2 application framing after handshake is disconnected")
        empty.send_raw_message(empty.v2_state.v2_enc_packet(b'\x12' + b'\x00' * 8))
        empty.wait_for_disconnect()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        self.log.info("addnode v2transport=false is invalid")
        ip_port = "127.0.0.1:{}".format(p2p_port(0))
        assert_raises_rpc_error(-8, "Error: v1 transport is not offered",
                                node.addnode, node=ip_port, command='add', v2transport=False)

        self.log.info("-v2transport is not a node option")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=["-v2transport=1"],
            expected_msg="Invalid parameter -v2transport",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        node.assert_start_raises_init_error(
            extra_args=["-v2transport=0"],
            expected_msg="Invalid parameter -v2transport",
            match=ErrorMatch.PARTIAL_REGEX,
        )


if __name__ == '__main__':
    P2PV3Rejected(__file__).main()
