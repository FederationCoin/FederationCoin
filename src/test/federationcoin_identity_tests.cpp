// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <key_io.h>
#include <outputtype.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(federationcoin_identity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(chain_params_identity)
{
    constexpr std::string_view headline{"09/Sep/2026 FederationCoin: time is the unit, not the state"};
    const CScript genesis_spk = CScript() << std::vector<unsigned char>(33, 0x00) << OP_CHECKSIG;

    const std::array chains{
        ChainType::MAIN,
        ChainType::TESTNET,
        ChainType::TESTNET4,
        ChainType::SIGNET,
        ChainType::REGTEST,
    };
    for (const ChainType chain : chains) {
        const auto params{CreateChainParams(ArgsManager{}, chain)};
        const auto base{CreateBaseChainParams(chain)};
        const Consensus::Params& c{params->GetConsensus()};
        BOOST_CHECK_EQUAL(c.BIP34Height, 1);
        BOOST_CHECK_EQUAL(c.BIP65Height, 1);
        BOOST_CHECK_EQUAL(c.BIP66Height, 1);
        BOOST_CHECK_EQUAL(c.CSVHeight, 1);
        BOOST_CHECK_EQUAL(c.SegwitHeight, 1);
        BOOST_CHECK_EQUAL(params->Checkpoints().GetHeight(), 0);
        BOOST_CHECK_EQUAL(c.Blake2bHeight, 1);
        BOOST_CHECK_EQUAL(c.Blake2bTargetShift, 0);
        BOOST_CHECK_EQUAL(c.RdtsExpiryTime, 1819756800);
        BOOST_CHECK(c.Blake2bHeadline.size() == headline.size());
        BOOST_CHECK(std::equal(headline.begin(), headline.end(), c.Blake2bHeadline.begin()));
        BOOST_CHECK_EQUAL(c.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime,
                          Consensus::BIP9Deployment::NEVER_ACTIVE);
        BOOST_CHECK(params->GenesisBlock().vtx[0]->vout[0].scriptPubKey == genesis_spk);
        BOOST_CHECK(params->FixedSeeds().empty());
        BOOST_CHECK(GetNetworkForMagic(params->MessageStart()) == chain);

        switch (chain) {
        case ChainType::MAIN:
            BOOST_CHECK_EQUAL(params->GetDefaultPort(), 4095);
            BOOST_CHECK_EQUAL(base->RPCPort(), 4094);
            BOOST_CHECK_EQUAL(params->Bech32HRP(), "gfcn");
            BOOST_CHECK_EQUAL(params->MessageStart()[0], 0x00);
            BOOST_CHECK_EQUAL(params->MessageStart()[1], 0x00);
            BOOST_CHECK_EQUAL(params->MessageStart()[2], 0x00);
            BOOST_CHECK_EQUAL(params->MessageStart()[3], 0x00);
            BOOST_CHECK_EQUAL(params->GenesisBlock().nBits, 0x1e00ffff);
            BOOST_CHECK_EQUAL(c.nMinDifficultyBits, 0U);
            BOOST_CHECK(c.powLimit == uint256{"000000ffff000000000000000000000000000000000000000000000000000000"});
            BOOST_CHECK(params->DNSSeeds().empty());
            BOOST_CHECK(DummyMainNeedsWarning(chain));
            break;
        case ChainType::TESTNET:
            BOOST_CHECK_EQUAL(params->GetDefaultPort(), 35333);
            BOOST_CHECK_EQUAL(base->RPCPort(), 35332);
            BOOST_CHECK_EQUAL(params->Bech32HRP(), "tgfcn");
            BOOST_CHECK_EQUAL(params->MessageStart()[0], 0xfc);
            BOOST_CHECK_EQUAL(params->MessageStart()[1], 0xe3);
            BOOST_CHECK_EQUAL(params->MessageStart()[2], 0x1e);
            BOOST_CHECK_EQUAL(params->MessageStart()[3], 0xc3);
            BOOST_CHECK_EQUAL(params->GenesisBlock().nBits, 0x1d00ffff);
            BOOST_CHECK_EQUAL(c.nMinDifficultyBits, 0x1b095caeU);
            BOOST_CHECK(c.powLimit == uint256{"000000ffff000000000000000000000000000000000000000000000000000000"});
            BOOST_REQUIRE_EQUAL(params->DNSSeeds().size(), 1U);
            BOOST_CHECK_EQUAL(params->DNSSeeds().front(), "seed.testnet.federationcoin.org.");
            BOOST_CHECK(!DummyMainNeedsWarning(chain));
            break;
        case ChainType::TESTNET4:
            BOOST_CHECK_EQUAL(params->GetDefaultPort(), 45333);
            BOOST_CHECK_EQUAL(base->RPCPort(), 45332);
            BOOST_CHECK_EQUAL(params->Bech32HRP(), "tgfcn");
            BOOST_CHECK_EQUAL(params->MessageStart()[0], 0xfc);
            BOOST_CHECK_EQUAL(params->MessageStart()[1], 0xe4);
            BOOST_CHECK_EQUAL(params->MessageStart()[2], 0x1e);
            BOOST_CHECK_EQUAL(params->MessageStart()[3], 0xc4);
            BOOST_CHECK_EQUAL(params->GenesisBlock().nBits, 0x1d00ffff);
            BOOST_CHECK_EQUAL(c.nMinDifficultyBits, 0U);
            BOOST_CHECK(params->DNSSeeds().empty());
            BOOST_CHECK(!DummyMainNeedsWarning(chain));
            break;
        case ChainType::SIGNET:
            BOOST_CHECK_EQUAL(params->GetDefaultPort(), 26333);
            BOOST_CHECK_EQUAL(base->RPCPort(), 26332);
            BOOST_CHECK_EQUAL(params->Bech32HRP(), "tgfcn");
            BOOST_CHECK_EQUAL(params->GenesisBlock().nBits, 0x1e0377ae);
            BOOST_CHECK_EQUAL(c.nMinDifficultyBits, 0U);
            BOOST_CHECK(c.powLimit == uint256{"00000377ae000000000000000000000000000000000000000000000000000000"});
            BOOST_CHECK(params->DNSSeeds().empty());
            BOOST_CHECK(!DummyMainNeedsWarning(chain));
            break;
        case ChainType::REGTEST:
            BOOST_CHECK_EQUAL(params->GetDefaultPort(), 25444);
            BOOST_CHECK_EQUAL(base->RPCPort(), 25443);
            BOOST_CHECK_EQUAL(params->Bech32HRP(), "gfcnrt");
            BOOST_CHECK_EQUAL(params->MessageStart()[0], 0xfc);
            BOOST_CHECK_EQUAL(params->MessageStart()[1], 0xe7);
            BOOST_CHECK_EQUAL(params->MessageStart()[2], 0x1e);
            BOOST_CHECK_EQUAL(params->MessageStart()[3], 0xc7);
            BOOST_CHECK_EQUAL(params->GenesisBlock().nBits, 0x207fffff);
            BOOST_CHECK_EQUAL(c.nMinDifficultyBits, 0U);
            BOOST_CHECK(c.powLimit == uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"});
            BOOST_CHECK(params->DNSSeeds().empty());
            BOOST_CHECK(!DummyMainNeedsWarning(chain));
            break;
        }
    }

    const MessageStartChars unknown{0xff, 0xfe, 0xfd, 0xfc};
    BOOST_CHECK(!GetNetworkForMagic(unknown));
}

BOOST_AUTO_TEST_CASE(testnet_blake2b_floor)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::TESTNET)};
    const Consensus::Params& c{params->GetConsensus()};
    BOOST_CHECK_EQUAL(c.nMinDifficultyBits, 0x1b095caeU);

    CBlockIndex genesis;
    genesis.nHeight = 0;
    genesis.nBits = params->GenesisBlock().nBits;
    genesis.nTime = params->GenesisBlock().nTime;

    CBlockHeader next;
    next.nTime = genesis.nTime + 60;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &next, c), 0x1b095caeU);

    next.nTime = genesis.nTime + 21 * 60;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &next, c), 0x1b095caeU);
}

BOOST_AUTO_TEST_CASE(output_type_is_allowed_forks)
{
    BOOST_CHECK(OutputTypeIsAllowed(OutputType::LEGACY));
    BOOST_CHECK(OutputTypeIsAllowed(OutputType::P2SH_SEGWIT));
    BOOST_CHECK(OutputTypeIsAllowed(OutputType::BECH32));
    BOOST_CHECK(OutputTypeIsAllowed(OutputType::UNKNOWN));
    BOOST_CHECK(!OutputTypeIsAllowed(OutputType::BECH32M));

    const auto parked{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    BOOST_CHECK(!OutputTypeIsAllowed(OutputType::BECH32M, parked->GetConsensus()));
    BOOST_CHECK(OutputTypeIsAllowed(OutputType::BECH32, parked->GetConsensus()));

    Consensus::Params taproot_on{parked->GetConsensus()};
    taproot_on.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
    BOOST_CHECK(OutputTypeIsAllowed(OutputType::BECH32M, taproot_on));
    BOOST_CHECK(OutputTypeIsAllowed(OutputType::BECH32, taproot_on));
}

BOOST_AUTO_TEST_CASE(format_subversion_true_equals_false)
{
    BOOST_CHECK_EQUAL(UA_NAME, "Sumer");
    const std::vector<std::string> comments{"comment1"};
    BOOST_CHECK_EQUAL(FormatSubVersion(UA_NAME, CLIENT_VERSION, {}),
                      FormatSubVersion(UA_NAME, CLIENT_VERSION, {}, true));
    BOOST_CHECK_EQUAL(FormatSubVersion(UA_NAME, CLIENT_VERSION, comments, false),
                      FormatSubVersion(UA_NAME, CLIENT_VERSION, comments, true));
}

BOOST_AUTO_TEST_CASE(taproot_v1_spend_fail_closed)
{
    CScript spk;
    spk << OP_1 << std::vector<unsigned char>(WITNESS_V1_TAPROOT_SIZE, 0x02);
    CScriptWitness wit;
    ScriptError err{SCRIPT_ERR_OK};
    const unsigned int flags_off{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS};
    BOOST_CHECK(!VerifyScript(CScript(), spk, &wit, flags_off, BaseSignatureChecker(), &err));
    BOOST_CHECK(err == SCRIPT_ERR_TAPROOT_DISABLED);

    err = SCRIPT_ERR_OK;
    const unsigned int flags_on{flags_off | SCRIPT_VERIFY_TAPROOT};
    BOOST_CHECK(!VerifyScript(CScript(), spk, &wit, flags_on, BaseSignatureChecker(), &err));
    BOOST_CHECK(err == SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
}

BOOST_AUTO_TEST_CASE(bech32m_not_a_destination_while_parked)
{
    BOOST_CHECK(!IsValidDestination(WitnessV1Taproot{}));
    const std::string addr{EncodeDestination(WitnessV1Taproot{})};
    std::string error;
    const CTxDestination dest{DecodeDestination(addr, error)};
    BOOST_CHECK(!IsValidDestination(dest));
    BOOST_CHECK(error.find("Bech32m") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(v1_outputs_rejected_unless_taproot_enabled)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1;
    mtx.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(WITNESS_V1_TAPROOT_SIZE, 0x02);
    const CTransaction tx{mtx};

    const auto parked{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    TxValidationState state_off;
    BOOST_CHECK(!Consensus::CheckTaprootDisabledOutputs(tx, parked->GetConsensus(), state_off));
    BOOST_CHECK_EQUAL(state_off.GetRejectReason(), "bad-txns-vout-taproot-disabled");

    Consensus::Params taproot_on{parked->GetConsensus()};
    taproot_on.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
    TxValidationState state_on;
    BOOST_CHECK(Consensus::CheckTaprootDisabledOutputs(tx, taproot_on, state_on));

    CMutableTransaction mtx_v0{mtx};
    mtx_v0.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(WITNESS_V0_KEYHASH_SIZE, 0x03);
    TxValidationState state_v0;
    BOOST_CHECK(Consensus::CheckTaprootDisabledOutputs(CTransaction{mtx_v0}, parked->GetConsensus(), state_v0));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(federationcoin_identity_chainman_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(taproot_not_active_so_block_flags_omit_it)
{
    LOCK(::cs_main);
    const CBlockIndex* genesis{Assert(m_node.chainman)->ActiveChain().Genesis()};
    BOOST_REQUIRE(genesis);
    BOOST_CHECK(!DeploymentActiveAt(*genesis, *m_node.chainman, Consensus::DEPLOYMENT_TAPROOT));
}

BOOST_AUTO_TEST_SUITE_END()
