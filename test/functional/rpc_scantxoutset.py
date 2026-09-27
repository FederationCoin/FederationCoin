#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the scantxoutset rpc call."""
from test_framework.address import address_to_scriptpubkey
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import (
    MiniWallet,
    getnewdestination,
)

from decimal import Decimal


def descriptors(out):
    return sorted(u['desc'] for u in out['unspents'])


class ScantxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def sendtodestination(self, destination, amount):
        # interpret strings as addresses, assume scriptPubKey otherwise
        if isinstance(destination, str):
            destination = address_to_scriptpubkey(destination)
        self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=destination, amount=int(COIN * amount))

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.log.info("Test if we find coinbase outputs.")
        assert_equal(sum(u["coinbase"] for u in self.nodes[0].scantxoutset("start", [self.wallet.get_descriptor()])["unspents"]), 49)

        self.log.info("Create UTXOs...")
        pubk1, spk_P2SH_SEGWIT, addr_P2SH_SEGWIT = getnewdestination("p2sh-segwit")
        pubk2, spk_LEGACY, addr_LEGACY = getnewdestination("legacy")
        pubk3, spk_BECH32, addr_BECH32 = getnewdestination("bech32")
        self.sendtodestination(spk_P2SH_SEGWIT, 0.001)
        self.sendtodestination(spk_LEGACY, 0.002)
        self.sendtodestination(spk_BECH32, 0.004)

        #send to child keys of trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX
        self.sendtodestination("fJsqFTKgypEKiYD4AqR2C2th1pfrikC2CD", 0.008)  # (m/0'/0'/0')
        self.sendtodestination("fHQpggzgoqcJmoDYUg5o2NnPiQggiYkKPS", 0.016)  # (m/0'/0'/1')
        self.sendtodestination("fbhyQXsUzwbGBQvVfsmkVDtH9Ci1p9qw9q", 0.032)  # (m/0'/0'/1500')
        self.sendtodestination("fQ2Vg5uXRUv9v21raAM9aCSQD7ki4dFtnY", 0.064)  # (m/0'/0'/0)
        self.sendtodestination("fM42KwiuVASacMLwLbb1UDt232Sjud3W5M", 0.128)  # (m/0'/0'/1)
        self.sendtodestination("fKFEStKZnajTZhnKpAViTHwbDbockAc259", 0.256)  # (m/0'/0'/1500)
        self.sendtodestination("fHjLWG5ypjDZRbaYogghdYiFej4QaKrxqC", 0.512)  # (m/1/1/0')
        self.sendtodestination("fENg4addK1NhVrzdKpaFbe2pPyGPRLeWic", 1.024)  # (m/1/1/1')
        self.sendtodestination("fNVSrSF9DVbmHN7dV9eQLY5MiYwnKAUN8Q", 2.048)  # (m/1/1/1500')
        self.sendtodestination("fTFq3jpLnSesuaw3SDghhGbvujgbTG1e7F", 4.096)  # (m/1/1/0)
        self.sendtodestination("fXQUBNxX57kp1Pu4VihJ5VaJozABdEd3G2", 8.192)  # (m/1/1/1)
        self.sendtodestination("fNzV74yZLvbS5x522Nuzha8Bf6Per59Gcx", 16.384)  # (m/1/1/1500)

        self.generate(self.nodes[0], 1)

        scan = self.nodes[0].scantxoutset("start", [])
        info = self.nodes[0].gettxoutsetinfo()
        assert_equal(scan['success'], True)
        assert_equal(scan['height'], info['height'])
        assert_equal(scan['txouts'], info['txouts'])
        assert_equal(scan['bestblock'], info['bestblock'])

        self.log.info("Test if we have found the non HD unspent outputs.")
        assert_equal(self.nodes[0].scantxoutset("start", ["pkh(" + pubk1.hex() + ")", "pkh(" + pubk2.hex() + ")", "pkh(" + pubk3.hex() + ")"])['total_amount'], Decimal("0.002"))
        assert_equal(self.nodes[0].scantxoutset("start", ["wpkh(" + pubk1.hex() + ")", "wpkh(" + pubk2.hex() + ")", "wpkh(" + pubk3.hex() + ")"])['total_amount'], Decimal("0.004"))
        assert_equal(self.nodes[0].scantxoutset("start", ["sh(wpkh(" + pubk1.hex() + "))", "sh(wpkh(" + pubk2.hex() + "))", "sh(wpkh(" + pubk3.hex() + "))"])['total_amount'], Decimal("0.001"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(" + pubk1.hex() + ")", "combo(" + pubk2.hex() + ")", "combo(" + pubk3.hex() + ")"])['total_amount'], Decimal("0.007"))
        assert_equal(self.nodes[0].scantxoutset("start", ["addr(" + addr_P2SH_SEGWIT + ")", "addr(" + addr_LEGACY + ")", "addr(" + addr_BECH32 + ")"])['total_amount'], Decimal("0.007"))
        assert_equal(self.nodes[0].scantxoutset("start", ["addr(" + addr_P2SH_SEGWIT + ")", "addr(" + addr_LEGACY + ")", "combo(" + pubk3.hex() + ")"])['total_amount'], Decimal("0.007"))

        self.log.info("Test range validation.")
        assert_raises_rpc_error(-8, "End of range is too high", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": -1}])
        assert_raises_rpc_error(-8, "Range should be greater or equal than 0", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [-1, 10]}])
        assert_raises_rpc_error(-8, "End of range is too high", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [(2 << 31 + 1) - 1000000, (2 << 31 + 1)]}])
        assert_raises_rpc_error(-8, "Range specified as [begin,end] must not have begin after end", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [2, 1]}])
        assert_raises_rpc_error(-8, "Range is too large", self.nodes[0].scantxoutset, "start", [{"desc": "desc", "range": [0, 1000001]}])

        self.log.info("Test extended key derivation.")
        # Run various scans, and verify that the sum of the amounts of the matches corresponds to the expected subset.
        # Note that all amounts in the UTXO set are powers of 2 multiplied by 0.001 BTC, so each amounts uniquely identifies a subset.
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0'/0h/0h)"])['total_amount'], Decimal("0.008"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0'/0'/1h)"])['total_amount'], Decimal("0.016"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0h/0'/1500')"])['total_amount'], Decimal("0.032"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0h/0h/0)"])['total_amount'], Decimal("0.064"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0'/0h/1)"])['total_amount'], Decimal("0.128"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0h/0'/1500)"])['total_amount'], Decimal("0.256"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0'/0h/*h)", "range": 1499}])['total_amount'], Decimal("0.024"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0'/0'/*h)", "range": 1500}])['total_amount'], Decimal("0.056"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0h/0'/*)", "range": 1499}])['total_amount'], Decimal("0.192"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0'/0h/*)", "range": 1500}])['total_amount'], Decimal("0.448"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/0')"])['total_amount'], Decimal("0.512"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/1')"])['total_amount'], Decimal("1.024"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/1500h)"])['total_amount'], Decimal("2.048"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/0)"])['total_amount'], Decimal("4.096"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/1)"])['total_amount'], Decimal("8.192"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/1500)"])['total_amount'], Decimal("16.384"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trB6nMbsSD2SBxuhNXhn4z1LDdKasWu6ENda7foJDVBd31u37KcqP9syhfEAfn5HgCiY6rxNjEhDYXuywbHJNZaEumJ3nkHfi9C2GGVfBBYBGEB/1/1/0)"])['total_amount'], Decimal("4.096"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo([abcdef88/1/2'/3/4h]trB6nMbsSD2SBxuhNXhn4z1LDdKasWu6ENda7foJDVBd31u37KcqP9syhfEAfn5HgCiY6rxNjEhDYXuywbHJNZaEumJ3nkHfi9C2GGVfBBYBGEB/1/1/1)"])['total_amount'], Decimal("8.192"))
        assert_equal(self.nodes[0].scantxoutset("start", ["combo(trB6nMbsSD2SBxuhNXhn4z1LDdKasWu6ENda7foJDVBd31u37KcqP9syhfEAfn5HgCiY6rxNjEhDYXuywbHJNZaEumJ3nkHfi9C2GGVfBBYBGEB/1/1/1500)"])['total_amount'], Decimal("16.384"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/*')", "range": 1499}])['total_amount'], Decimal("1.536"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/*')", "range": 1500}])['total_amount'], Decimal("3.584"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/*)", "range": 1499}])['total_amount'], Decimal("12.288"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/*)", "range": 1500}])['total_amount'], Decimal("28.672"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trB6nMbsSD2SBxuhNXhn4z1LDdKasWu6ENda7foJDVBd31u37KcqP9syhfEAfn5HgCiY6rxNjEhDYXuywbHJNZaEumJ3nkHfi9C2GGVfBBYBGEB/1/1/*)", "range": 1499}])['total_amount'], Decimal("12.288"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trB6nMbsSD2SBxuhNXhn4z1LDdKasWu6ENda7foJDVBd31u37KcqP9syhfEAfn5HgCiY6rxNjEhDYXuywbHJNZaEumJ3nkHfi9C2GGVfBBYBGEB/1/1/*)", "range": 1500}])['total_amount'], Decimal("28.672"))
        assert_equal(self.nodes[0].scantxoutset("start", [{"desc": "combo(trB6nMbsSD2SBxuhNXhn4z1LDdKasWu6ENda7foJDVBd31u37KcqP9syhfEAfn5HgCiY6rxNjEhDYXuywbHJNZaEumJ3nkHfi9C2GGVfBBYBGEB/1/1/*)", "range": [1500, 1500]}])['total_amount'], Decimal("16.384"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "pkh(trB6nMbsSD2SBxuhNXhn4z1LDdKasWu6ENda7foJDVBd31u37KcqP9syhfEAfn5HgCiY6rxNjEhDYXuywbHJNZaEumJ3nkHfi9C2GGVfBBYBGEB/1/1/<0;1>)"}])["total_amount"], Decimal("12.288"))

        # Test the reported descriptors for a few matches
        assert_equal(descriptors(self.nodes[0].scantxoutset("start", [{"desc": "combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/0h/0h/*)", "range": 1499}])), ["pkh([0c5f9a1e/0h/0h/0]026dbd8b2315f296d36e6b6920b1579ca75569464875c7ebe869b536a7d9503c8c)#rthll0rg", "pkh([0c5f9a1e/0h/0h/1]033e6f25d76c00bedb3a8993c7d5739ee806397f0529b1b31dda31ef890f19a60c)#mcjajulr"])
        assert_equal(descriptors(self.nodes[0].scantxoutset("start", ["combo(trBb8nVXuTDmeQ5gSxZupKuXyGakGRZ1zezXMdZ6FYRhWGWqDcg1xA2zyEaP47ncsZh3eChauxW3wrzhkmB9aRwGo4ALVH1aNjTCRz29qdGVCeX/1/1/0)"])), ["pkh([0c5f9a1e/1/1/0]03e1c5b6e650966971d7e71ef2674f80222752740fc1dfd63bbbd220d2da9bd0fb)#cxmct4w8"])
        assert_equal(descriptors(self.nodes[0].scantxoutset("start", [{"desc": "combo(trB6nMbsSD2SBxuhNXhn4z1LDdKasWu6ENda7foJDVBd31u37KcqP9syhfEAfn5HgCiY6rxNjEhDYXuywbHJNZaEumJ3nkHfi9C2GGVfBBYBGEB/1/1/*)", "range": 1500}])), ['pkh([0c5f9a1e/1/1/0]03e1c5b6e650966971d7e71ef2674f80222752740fc1dfd63bbbd220d2da9bd0fb)#cxmct4w8', 'pkh([0c5f9a1e/1/1/1500]03832901c250025da2aebae2bfb38d5c703a57ab66ad477f9c578bfbcd78abca6f)#vchwd07g', 'pkh([0c5f9a1e/1/1/1]030d820fc9e8211c4169be8530efbc632775d8286167afd178caaf1089b77daba7)#z2t3ypsa'])

        # Check that status and abort don't need second arg
        assert_equal(self.nodes[0].scantxoutset("status"), None)
        assert_equal(self.nodes[0].scantxoutset("abort"), False)

        # Check that the blockhash and confirmations fields are correct
        self.generate(self.nodes[0], 2)
        unspent = self.nodes[0].scantxoutset("start", ["addr(fNzV74yZLvbS5x522Nuzha8Bf6Per59Gcx)"])["unspents"][0]
        blockhash = self.nodes[0].getblockhash(info["height"])
        assert_equal(unspent["height"], info["height"])
        assert_equal(unspent["blockhash"], blockhash)
        assert_equal(unspent["confirmations"], 3)

        # Check that first arg is needed
        assert_raises_rpc_error(-1, "scantxoutset \"action\" ( [scanobjects,...] )", self.nodes[0].scantxoutset)

        # Check that second arg is needed for start
        assert_raises_rpc_error(-1, "scanobjects argument is required for the start action", self.nodes[0].scantxoutset, "start")

        # Check that invalid command give error
        assert_raises_rpc_error(-8, "Invalid action 'invalid_command'", self.nodes[0].scantxoutset, "invalid_command")


if __name__ == "__main__":
    ScantxoutsetTest(__file__).main()
