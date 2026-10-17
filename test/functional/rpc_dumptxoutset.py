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
            '3165fbdf72d9b7d03bd24fb47e54ca30b75ed3d26663f8bc6e28c8470dd034b8')

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
            out['txoutset_hash'], '1e698e6809110f8fa45e718c842590d6e1cc075c4582d425db2d6a8d2ebc02ee')
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
                        "#(blockhash 3165fbdf72d9b7d03bd24fb47e54ca30b75ed3d26663f8bc6e28c8470dd034b8 ) txid{s}vout{s}value{s}coinbase{s}height{s}scriptPubKey".format(s=sep))
                assert_equal(content[0].rstrip(),
                    "396ec5e18b7f76b37cf1eb120404c15c773a01fbf0e4b4f736f78a0d118d7500{s}0{s}5000000000{s}1{s}21{s}00142b4569203694fc997e13f2c0a1383b9e16c77a0d".format(s=sep))

    def run_test(self):
        """Test a trivial usage of the dumptxoutset RPC command."""
        node = self.nodes[0]
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 1
        node.setmocktime(mocktime)
        self.generate(node, COINBASE_MATURITY)

        self.test_dump_file('no_option',           {},
                            '927ef4a287db4026705e7601e3571c612f79fee3e2fda9be771af6cee6b14c4d')
        self.test_dump_file('all_data',            {'format': ()},
                            '77c48f480a7584e6eb529a1f4c7807c122e00541356301890f98b7d23141add0')
        self.test_dump_file('partial_data_1',      {'format': ('txid',)},
                            'e7e455a85b9d1b656754b4a1ffdb5e50665d64f9bbc6a9b6b6fce362a2e301bf')
        self.test_dump_file('partial_data_order',  {'format': ('height', 'vout')},
                            'b5504008b03ac6c1ad6af57c977bf687abb89ccc820843e2649662e08c3b3375')
        self.test_dump_file('partial_data_double', {'format': ('scriptPubKey', 'scriptPubKey')},
                            '69c7dd571f1a004e85a7335c1f16976104e7e98f34031c04400e5b93f9dc1ce1')
        self.test_dump_file('no_header',           {'format': (), 'show_header': False},
                            '9fe63e1b378d9d3b6a02657c933c352069d48eecc72c3f9f1b1b2093e969bf02')
        self.test_dump_file('separator',           {'format': (), 'separator': ':'},
                            'd0aa9311bfb95a9a5be6197dca3dc1059c8b2dabe643ef3c174dbf21d0a0c6c9')
        self.test_dump_file('all_options',         {'format': (), 'show_header': False, 'separator': ':'},
                            '81c40851439597b7870972a9d036121da6170aad140e429c56563d348cecb99f')

        # Other failing tests
        assert_raises_rpc_error(
            -8, 'unable to find item \'sample\'',  node.dumptxoutset, path='xxx', type='latest', format=['sample'])

if __name__ == '__main__':
    DumptxoutsetTest(__file__).main()
