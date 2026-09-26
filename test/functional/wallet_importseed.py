#!/usr/bin/env python3
# Copyright (c) 2013 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the 'seeds' argument to the importdescriptors RPC

Test importingi seeds by using the BIP 93 test vectors to verify that imported
seeds are compatible with descriptors containing the corresponding xpubs, that
the wallet is able to recognize and send funds, and that the wallet can derive
addresses, when given only seeds as private data."""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_raises_rpc_error,
)


class ImportDescriptorsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        test_start = int(time.time())

        # Spend/receive tests
        self.nodes[0].createwallet(wallet_name='w0', descriptors=True)
        self.nodes[0].createwallet(wallet_name='w1', descriptors=True, blank=True)
        w0 = self.nodes[0].get_wallet_rpc('w0')
        w1 = self.nodes[0].get_wallet_rpc('w1')

        self.generatetoaddress(self.nodes[0], 2, w0.getnewaddress())
        self.generate(self.nodes[0], 100)

        # Test 1: send coins to wallet, check they are not received, then import
        #         the descriptor and make sure they are recognized. Send them
        #         back and repeat. Uses single codex32 seed.
        #
        # xpub converted from BIP 93 test vector 1 xpriv using rust-bitcoin
        xpub = "trB6nMbsSD2SBxuhQ833245rztoMVE8NdiXHrDN1YHypfqDaG3B3x2Ubfrk8NrcwNVb1s8VzVYmM5qHf1F59pTVkD75m1pP3hWERYG2G3ZAZtr3"
        descriptors = [
            f"wsh(pk({xpub}/55/*))",
            f"tr({xpub}/1/2/3/4/5/*)",
            f"pkh({xpub}/*)",
            f"wpkh({xpub}/*)",
            f"rawtr({xpub}/1/2/3/*)",
        ]
        assert_raises_rpc_error(-4, "This wallet has no available keys", w1.getnewaddress)
        for descriptor in descriptors:
            descriptor_chk = w0.getdescriptorinfo(descriptor)["descriptor"]
            addr = w0.deriveaddresses(descriptor_chk, range=[0, 20])[0]
            if descriptor.startswith("tr(") or descriptor.startswith("rawtr("):
                assert_raises_rpc_error(-5, "Invalid Bitcoin address", w0.sendtoaddress, addr, 95)
                continue

            assert w0.getbalance() > 99  # sloppy balance checks, to account for fees
            w0.sendtoaddress(addr, 95)
            self.generate(self.nodes[0], 1)
            assert w0.getbalance() < 5

            w1.importdescriptors(
                [{"desc": descriptor_chk, "timestamp": test_start, "range": 0, "active": True}],
                [["ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw"]],
            )

            assert w1.getbalance() > 94
            w1.sendtoaddress(w0.getnewaddress(), 95, "", "", True)
            self.generate(self.nodes[0], 1)
            assert w0.getbalance() > 99
        w1.getnewaddress()  # no failure now

        # Test 2: deriveaddresses on hardened keys fails before import, succeeds after.
        #         Uses single codex32 seed in 2 shares.
        #
        # xpub converted from BIP 93 test vector 2 xpriv using rust-bitcoin
        self.nodes[0].createwallet(wallet_name='w2', descriptors=True, blank=True)
        w2 = self.nodes[0].get_wallet_rpc('w2')

        xpub = "trB6nMbsSD2SBxuhNcDTF2dTuPy7dkFYiChUa5mmk5AaY76URAwBExhohHFHtfoFwU8Bb9D2vLvRbQny7HwpVMD2RbMFSfgnV2bFF8stFgojdqV"
        descriptor = f"tr([fab6868a/1h/2]{xpub}/1h/2/*h)"
        descriptor_chk = w2.getdescriptorinfo(descriptor)["descriptor"]
        assert_raises_rpc_error(
            -4,
            "This wallet has no available keys",
            w2.getnewaddress,
            address_type="bech32m",
        )

        # Try importing descriptor with wrong seed
        err = w2.importdescriptors(
            [{"desc": descriptor_chk, "timestamp": test_start, "active": True, "range": [0, 20]}],
            [["ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw"]],
        )
        assert "Cannot expand descriptor." in err[0]["error"]["message"]
        assert_raises_rpc_error(
            -4,
            "This wallet has no available keys",
            w2.getnewaddress,
            address_type="bech32m",
        )

        # Try various failure cases
        assert_raises_rpc_error(
            -5,
            "single share must be the S share",
            w2.importdescriptors,
            [{"desc": descriptor_chk, "timestamp": test_start, "active": True, "range": [0, 20]}],
            [["MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM"]],
        )

        assert_raises_rpc_error(
            -5,
            "two input shares had the same index",
            w2.importdescriptors,
            [{"desc": descriptor_chk, "timestamp": test_start, "active": True, "range": [0, 20]}],
            [[
                "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
                "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
            ]],
        )

        assert_raises_rpc_error(
            -5,
            "input shares had inconsistent seed IDs",
            w2.importdescriptors,
            [{"desc": descriptor_chk, "timestamp": test_start, "active": True, "range": [0, 20]}],
            [[
                "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
                "ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr",
            ]],
        )

        # Do it correctly
        w2.importdescriptors(
            [{"desc": descriptor_chk, "timestamp": test_start, "active": True, "range": [0, 20]}],
            [[
                "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
                "MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN",
            ]],
        )
        # Taproot stays disabled even after the seed imports.
        assert_raises_rpc_error(
            -5,
            "Bech32m / Taproot addresses are not valid on this chain.",
            w2.getnewaddress,
            address_type="bech32m",
        )
        assert_raises_rpc_error(
            -5,
            "Cannot derive script without private keys",
            w2.deriveaddresses,
            descriptor_chk,
            0,
        )
        # Do it again, to see if nothing breaks
        w2.importdescriptors(
            [{"desc": descriptor_chk, "timestamp": test_start, "active": True, "range": [0, 20]}],
            [[
                "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
                "MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN",
            ]],
        )

        # Test 3: multiple seeds, multiple descriptors
        #
        # xpubs converted from BIP 93 test vector 3, 4 and 5 xprivs using rust-bitcoin

        self.nodes[0].createwallet(wallet_name='w3', descriptors=True, blank=True)
        w3 = self.nodes[0].get_wallet_rpc('w3')
        xpub1 = "trB6nMbsSD2SBxuhNKZV82BjMHJirB8ooTZ3WKWz8ywQNy46nCxxD7uhes4EGiGFnbEBzuc11NYmvSnLKyLwgfKvPCPCrwNcniRqK7MCb8RG3Wo"  # vector 3
        xpub2 = "trB6nMbsSD2SBxuhQ6Wf7brTuCsLUNTMMBD8eyTXFVYKXzqoech4dFmG3rMPVvmDdHBc4pzuPSgCnBzCjJKty4Rmwr9EHib1AFbXgoHDyZEDuhU"  # vector 4
        xpub3 = "trB6nMbsSD2SBxuhQi16iFiYqJVBjWnv9C4MUZPfcTLpABpQTYPQqvmVZTh8boaLoU1w6M6osMNy8VywoNHvxjWaUVNwbDRM6UpdBfddudiw9dp"  # vector 5

        descriptor1 = f"rawtr({xpub1}/1/2h/*)"
        descriptor1_chk = w3.getdescriptorinfo(descriptor1)["descriptor"]
        descriptor2 = f"wpkh({xpub2}/1h/2/*)"
        descriptor2_chk = w3.getdescriptorinfo(descriptor2)["descriptor"]
        descriptor3 = f"pkh({xpub3}/1h/2/3/4/5/6/7/8/9/10/*)"
        descriptor3_chk = w3.getdescriptorinfo(descriptor3)["descriptor"]

        assert_raises_rpc_error(
            -4,
            "This wallet has no available keys",
            w3.getnewaddress,
            address_type="bech32m",
        )
        assert_raises_rpc_error(
            -4,
            "This wallet has no available keys",
            w3.getnewaddress,
            address_type="bech32",
        )
        assert_raises_rpc_error(
            -4,
            "This wallet has no available keys",
            w3.getnewaddress,
            address_type="legacy",
        )

        # First try without enough input shares.
        assert_raises_rpc_error(
            -5,
            "did not have enough input shares",
            w3.importdescriptors,
            [
                {"desc": descriptor1_chk, "timestamp": test_start, "active": True, "range": 10},
                {"desc": descriptor2_chk, "timestamp": test_start, "active": True, "range": 15},
            ],
            [[
                "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9",
                "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704",
            ], [
                "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma",
            ]],
        )
        # Wallet still doesn't work, even the descriptor whose seed was correctly specified
        assert_raises_rpc_error(
            -4,
            "This wallet has no available keys",
            w3.getnewaddress,
            address_type="bech32",
        )

        # Do it properly
        w3.importdescriptors(
            [
                {"desc": descriptor1_chk, "timestamp": test_start, "active": True, "range": 10},
                {"desc": descriptor2_chk, "timestamp": test_start, "active": True, "range": 15},
                {"desc": descriptor3_chk, "timestamp": test_start, "active": True, "range": 15},
            ],
            [[
                "ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm",
                "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9",
                "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704",
            ], [
                "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma",
            ]],
        )
        # All good now for the descriptor that had a seed. Taproot stays disabled.
        w3.getnewaddress(address_type="bech32")
        assert_raises_rpc_error(
            -5,
            "Bech32m / Taproot addresses are not valid on this chain.",
            w3.getnewaddress,
            address_type="bech32m",
        )
        # but the one without a seed still doesn't work
        assert_raises_rpc_error(
            -12,
            "No legacy addresses available",
            w3.getnewaddress,
            address_type="legacy",
        )

        # Ok, try to import the legacy one separately.
        w3.importdescriptors(
            [{"desc": descriptor3_chk, "timestamp": test_start, "active": True, "range": 15}],
            [["MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD"  # concat string
              "6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK"]],
        )
        # And all is well for legacy and bech32. Taproot stays disabled.
        w3.getnewaddress(address_type="bech32")
        assert_raises_rpc_error(
            -5,
            "Bech32m / Taproot addresses are not valid on this chain.",
            w3.getnewaddress,
            address_type="bech32m",
        )
        w3.getnewaddress(address_type="legacy")


if __name__ == '__main__':
    ImportDescriptorsTest(__file__).main()
