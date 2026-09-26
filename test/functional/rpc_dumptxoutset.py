#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the generation of UTXO snapshots using `dumptxoutset`.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    sha256sum_file,
)
import hashlib
import os


class DumptxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def check_expected_network(self, node, active):
        rev_file = node.blocks_path / "rev00000.dat"
        bogus_file = node.blocks_path / "bogus.dat"
        rev_file.rename(bogus_file)
        assert_raises_rpc_error(
            -1, 'Could not roll back to requested height.', node.dumptxoutset, 'utxos.dat', rollback=99)
        assert_equal(node.getnetworkinfo()['networkactive'], active)

        # Cleanup
        bogus_file.rename(rev_file)

    @staticmethod
    def check_output_file(path, is_human_readable, expected_digest):
        with open(str(path), 'rb') as f:
            content = f.read()

            if is_human_readable:
                # Normalise platform EOL to \n, while making sure any stray \n becomes a literal backslash+n to avoid a false positive
                # This ensures the platform EOL and only the platform EOL produces the expected hash
                linesep = os.linesep.encode('utf8')
                content = b'\n'.join(line.replace(b'\n', b'\\n') for line in content.split(linesep))

            digest = hashlib.sha256(content).hexdigest()
            # UTXO snapshot hash should be deterministic based on mocked time.
            assert_equal(digest, expected_digest)

    def test_dump_file(self, testname, params, expected_digest):
        node = self.nodes[0]

        self.log.info(testname)
        filename = testname + '_txoutset.dat'
        is_human_readable = not params.get('format') is None

        out = node.dumptxoutset(path=filename, type="latest", **params)
        expected_path = node.chain_path / filename

        assert expected_path.is_file()

        assert_equal(out['coins_written'], 100)
        assert_equal(out['base_height'], 100)
        assert_equal(out['path'], str(expected_path))
        # Blockhash should be deterministic based on mocked time.
        assert_equal(
            out['base_hash'],
            '4a641ef4032aa63254238c76b7b6bd314b0ae719fd0a3a5dd224ebdc1e128cd1')

        self.check_output_file(expected_path, is_human_readable, expected_digest)

        if {'format'} == set(params) - {'show_header', 'separator'}:
            # Test backward compatibility
            def test_dump_file_compat(*a, **ka):
                os.replace(expected_path, node.chain_path / (filename + ".old"))
                out2 = node.dumptxoutset(filename, *a, **ka)
                assert_equal(out, out2)
                self.check_output_file(expected_path, is_human_readable, expected_digest)
            test_dump_file_compat(params.get('format'), params.get('show_header'), params.get('separator'))
            test_dump_file_compat(params.get('format'), params.get('show_header'), separator=params.get('separator'))
            test_dump_file_compat(params.get('format'), show_header=params.get('show_header'), separator=params.get('separator'))

        assert_equal(
            out['txoutset_hash'], 'a0b7baa3bf5ccbd3279728f230d7ca0c44a76e9923fca8f32dbfd08d65ea496a')
        assert_equal(out['nchaintx'], 101)

        self.log.info("Test that a path to an existing or invalid file will fail")
        assert_raises_rpc_error(
            -8, '{} already exists'.format(filename),  node.dumptxoutset, filename, "latest")
        invalid_path = node.datadir_path / "invalid" / "path"
        assert_raises_rpc_error(
            -8, "Couldn't open file {}.incomplete for writing".format(invalid_path), node.dumptxoutset, invalid_path, "latest")

        self.log.info("Test that dumptxoutset with unknown dump type fails")
        assert_raises_rpc_error(
            -8, 'Invalid snapshot type "bogus" specified. Please specify "rollback" or "latest"', node.dumptxoutset, 'utxos.dat', "bogus")

        self.log.info("Test that dumptxoutset failure does not leave the network activity suspended when it was on previously")
        self.check_expected_network(node, True)

        self.log.info("Test that dumptxoutset failure leaves the network activity suspended when it was off")
        node.setnetworkactive(False)
        self.check_expected_network(node, False)
        node.setnetworkactive(True)

        if params.get('format') == ():
            with open(expected_path, 'r', encoding='utf-8') as f:
                content = f.readlines()
                sep = params.get('separator', ',')
                if params.get('show_header', True):
                    assert_equal(content.pop(0).rstrip(),
                        "#(blockhash 4a641ef4032aa63254238c76b7b6bd314b0ae719fd0a3a5dd224ebdc1e128cd1 ) txid{s}vout{s}value{s}coinbase{s}height{s}scriptPubKey".format(s=sep))
                assert_equal(content[0].rstrip(),
                    "b9edce02689692b1cdc3440d03011486a27c46b966248b922cc6e4315e900708{s}0{s}5000000000{s}1{s}78{s}76a9142b4569203694fc997e13f2c0a1383b9e16c77a0d88ac".format(s=sep))

    def run_test(self):
        """Test a trivial usage of the dumptxoutset RPC command."""
        node = self.nodes[0]
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 1
        node.setmocktime(mocktime)
        self.generate(node, COINBASE_MATURITY)

        self.test_dump_file('no_option',           {},
                            '08f12d68fca07502f700d4c1bcf9d2392a974045018a96e38baf6d1ac47d3d04')
        self.test_dump_file('all_data',            {'format': ()},
                            '3a0b29c4a9d0eb8ab16333c1711eb3c355a81de9b1afb64b9d7b72bdb359e91b')
        self.test_dump_file('partial_data_1',      {'format': ('txid',)},
                            '4d20911b7051ea037636e36cbaed782a2f0b1bf6d2901a98de8baea9fb41550f')
        self.test_dump_file('partial_data_order',  {'format': ('height', 'vout')},
                            'a700dccbcb18e472a854d5380ddc888d9a7bff6583836d6621998b16ac0c1cac')
        self.test_dump_file('partial_data_double', {'format': ('scriptPubKey', 'scriptPubKey')},
                            'f96c74be09d858da367f317eafce15b3f06cd4a8a4e1a62480f11a036492d4a4')
        self.test_dump_file('no_header',           {'format': (), 'show_header': False},
                            'af1f38ee1d1b8bbdc117ab7e8353910dab5ab45f18be27aa4fa7d96ccc96a050')
        self.test_dump_file('separator',           {'format': (), 'separator': ':'},
                            '95cb54638b51809538971e8c8b6872a8e31d241648b1a369dffd1222feaf9fc4')
        self.test_dump_file('all_options',         {'format': (), 'show_header': False, 'separator': ':'},
                            '5c52c2a9bdb23946eb0f6d088f25ed8f5d9ebc3a3512182287975f1041cdedb4')

        # Other failing tests
        assert_raises_rpc_error(
            -8, 'unable to find item \'sample\'',  node.dumptxoutset, path='xxx', type='latest', format=['sample'])

if __name__ == '__main__':
    DumptxoutsetTest(__file__).main()
