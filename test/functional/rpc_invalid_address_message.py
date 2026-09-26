#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test error messages for 'getaddressinfo' and 'validateaddress' RPC commands."""

from test_framework.test_framework import BitcoinTestFramework

from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

BECH32_VALID = 'gfcnrt1qtmp74ayg7p24uslctssvjm06q5phz4yr09x5l5'
BECH32_VALID_UNKNOWN_WITNESS = 'gfcnrt1p424qndmm36'
BECH32_VALID_CAPITALS = 'GFCNRT1QPLMTZKC2XHARPPZDLNPAQL78RSHJ68U3C6RTJM'
BECH32_VALID_MULTISIG = 'gfcnrt1qdg3myrgvzw7ml9q0ejxhlkyxm7vl9r56yzkfgvzclrf4hkpx9yfqsg7wfc'

BECH32_INVALID_BECH32 = 'gfcnrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq2jk98s'
BECH32_INVALID_BECH32M = 'gfcnrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kcd9lw4'
BECH32_INVALID_VERSION = 'gfcnrt130xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr6uth7'
BECH32_INVALID_SIZE = 'gfcnrt1s0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav25a8fk3q'
BECH32_INVALID_V0_SIZE = 'gfcnrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kqqygwav8'
BECH32_INVALID_PREFIX = 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx'
BECH32_TOO_LONG = 'bcrt1q049edschfnwystcqnsvyfpj23mpsg3jcedq9xv049edschfnwystcqnsvyfpj23mpsg3jcedq9xv049edschfnwystcqnsvyfpj23m'
BECH32_ONE_ERROR = 'bcrt1q049edschfnwystcqnsvyfpj23mpsg3jcedq9xv'
BECH32_ONE_ERROR_CAPITALS = 'BCRT1QPLMTZKC2XHARPPZDLNPAQL78RSHJ68U32RAH7R'
BECH32_TWO_ERRORS = 'bcrt1qax9suht3qv95sw33xavx8crpxduefdrsvgsklu' # should be gfcnrt1qax9suht3qv95sw33wavx8crpxduefdrs93w2n7
BECH32_NO_SEPARATOR = 'bcrtq049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv'
BECH32_INVALID_CHAR = 'bcrt1q04oldschfnwystcqnsvyfpj23mpsg3jcedq9xv'
BECH32_MULTISIG_TWO_ERRORS = 'bcrt1qdg3myrgvzw7ml8q0ejxhlkyxn7vl9r56yzkfgvzclrf4hkpx9yfqhpsuks'
BECH32_WRONG_VERSION = 'bcrt1ptmp74ayg7p24uslctssvjm06q5phz4yrxucgnv'

BASE58_VALID = 'fQna6UCypCszqVSDYdkbtmGiv2vAYP9zmo'
BASE58_INVALID_PREFIX = '17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem'
BASE58_INVALID_CHECKSUM = 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJJfn'
BASE58_INVALID_LENGTH = '2VKf7XKMrp4bVNVmuRbyCewkP8FhGLP2E54LHDPakr9Sq5mtU2'

INVALID_ADDRESS = 'asfah14i8fajz0123f'
INVALID_ADDRESS_2 = '1q049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv'

class InvalidAddressErrorMessageTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def check_valid(self, addr):
        info = self.nodes[0].validateaddress(addr)
        assert info['isvalid']
        assert 'error' not in info
        assert 'error_index' not in info
        assert 'error_locations' not in info

    def check_invalid(self, addr, error_str, error_locations=None):
        res = self.nodes[0].validateaddress(addr)
        if addr[:2] == 'bc':
            assert_equal(res, self.nodes[0].validateaddress(address=addr, address_type='bech32'))
        assert not res['isvalid']
        assert_equal(res['error'], error_str)
        if error_locations:
            assert_equal(res['error_index'], error_locations[0])
            assert_equal(res['error_locations'], error_locations)
        else:
            assert 'error_index' not in res
            assert_equal(res['error_locations'], [])

    def test_validateaddress(self):
        # Invalid deprecated address_type field
        assert_raises_rpc_error(-8, "Unknown address type 'nonsense'", self.nodes[0].validateaddress, address=BECH32_INVALID_SIZE, address_type='nonsense')
        for inv_addrtype in (7, True, {}, [], ['bech32']):
            assert_raises_rpc_error(-3, "is not of expected type string", self.nodes[0].validateaddress, address=BECH32_INVALID_SIZE, address_type=inv_addrtype)

        # Invalid Bech32
        taproot = 'Bech32m / Taproot addresses are not valid on this chain.'
        self.check_invalid(BECH32_INVALID_SIZE, taproot)
        self.check_invalid(BECH32_INVALID_PREFIX, 'Invalid or unsupported Segwit (Bech32) or Base58 encoding.')
        self.check_invalid(BECH32_INVALID_BECH32, 'Version 1+ witness address must use Bech32m checksum')
        self.check_invalid(BECH32_INVALID_BECH32M, 'Version 0 witness address must use Bech32 checksum')
        self.check_invalid(BECH32_INVALID_VERSION, taproot)
        self.check_invalid(BECH32_INVALID_V0_SIZE, "Invalid Bech32 v0 address program size (21 bytes), per BIP141")
        unsupported = 'Invalid or unsupported Segwit (Bech32) or Base58 encoding.'
        # These fixtures still use a foreign HRP, so the specific Bech32 diagnosis never runs.
        self.check_invalid(BECH32_TOO_LONG, unsupported)
        self.check_invalid(BECH32_ONE_ERROR, unsupported)
        self.check_invalid(BECH32_TWO_ERRORS, unsupported)
        self.check_invalid(BECH32_ONE_ERROR_CAPITALS, 'Invalid checksum or length of Base58 address (P2PKH or P2SH)')
        self.check_invalid(BECH32_NO_SEPARATOR, unsupported)
        self.check_invalid(BECH32_INVALID_CHAR, unsupported)
        self.check_invalid(BECH32_MULTISIG_TWO_ERRORS, unsupported)
        self.check_invalid(BECH32_WRONG_VERSION, unsupported)

        # Valid Bech32
        self.check_valid(BECH32_VALID)
        self.check_invalid(BECH32_VALID_UNKNOWN_WITNESS, 'Bech32m / Taproot addresses are not valid on this chain.')
        self.check_valid(BECH32_VALID_CAPITALS)
        self.check_valid(BECH32_VALID_MULTISIG)

        # Invalid Base58
        self.check_invalid(BASE58_INVALID_PREFIX, 'Invalid or unsupported Base58-encoded address.')
        self.check_invalid(BASE58_INVALID_CHECKSUM, 'Invalid checksum or length of Base58 address (P2PKH or P2SH)')
        self.check_invalid(BASE58_INVALID_LENGTH, 'Invalid checksum or length of Base58 address (P2PKH or P2SH)')

        # Valid Base58
        self.check_valid(BASE58_VALID)

        # Invalid address format
        self.check_invalid(INVALID_ADDRESS, 'Invalid or unsupported Segwit (Bech32) or Base58 encoding.')
        self.check_invalid(INVALID_ADDRESS_2, 'Invalid or unsupported Segwit (Bech32) or Base58 encoding.')

        node = self.nodes[0]

        # Missing arg returns the help text
        assert_raises_rpc_error(-1, "Return information about the given bitcoin address.", node.validateaddress)
        # Explicit None is not allowed for required parameters
        assert_raises_rpc_error(-3, "JSON value of type null is not of expected type string", node.validateaddress, None)

    def test_getaddressinfo(self):
        node = self.nodes[0]

        taproot = "Bech32m / Taproot addresses are not valid on this chain."
        assert_raises_rpc_error(-5, taproot, node.getaddressinfo, BECH32_INVALID_SIZE)
        assert_raises_rpc_error(-5, "Invalid or unsupported Segwit (Bech32) or Base58 encoding.", node.getaddressinfo, BECH32_INVALID_PREFIX)
        assert_raises_rpc_error(-5, "Invalid or unsupported Base58-encoded address.", node.getaddressinfo, BASE58_INVALID_PREFIX)
        assert_raises_rpc_error(-5, "Invalid or unsupported Segwit (Bech32) or Base58 encoding.", node.getaddressinfo, INVALID_ADDRESS)
        assert_raises_rpc_error(-5, taproot, node.getaddressinfo, BECH32_VALID_UNKNOWN_WITNESS)

    def run_test(self):
        self.test_validateaddress()

        if self.is_wallet_compiled():
            self.init_wallet(node=0)
            self.test_getaddressinfo()


if __name__ == '__main__':
    InvalidAddressErrorMessageTest(__file__).main()
