// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <type_traits>

using namespace util::hex_literals;

// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// A fix may be on the way:
// https://developercommunity.visualstudio.com/t/consteval-conversion-function-fails/1579014
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */

static const CScript UnspendableGenesisScript()
{
    return CScript() << "000000000000000000000000000000000000000000000000000000000000000000"_hex << OP_CHECKSIG;
}

static constexpr int64_t kFederationTaprootStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;

static void SetFederationBuriedBips(Consensus::Params& consensus)
{
    consensus.BIP34Height = 1;
    consensus.BIP34Hash = uint256{};
    consensus.BIP65Height = 1;
    consensus.BIP66Height = 1;
    consensus.CSVHeight = 1;
    consensus.SegwitHeight = 1;
    consensus.MinBIP9WarningHeight = 0;
}

static void SetFederationBlake2bAndRdts(Consensus::Params& consensus)
{
    consensus.Blake2bHeight = 1;
    consensus.Blake2bTargetShift = 0;
    {
        constexpr std::string_view headline = "09/Sep/2026 FederationCoin: time is the unit, not the state";
        consensus.Blake2bHeadline.assign(headline.begin(), headline.end());
    }
    consensus.RdtsExpiryTime = 1819756800; // September 1st, 2027 00:00 UTC (Knots value this pass)
}

static void SetFederationTaprootDeployment(Consensus::Params& consensus)
{
    consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
    consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = kFederationTaprootStartTime;
    consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
    consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        SetFederationBuriedBips(consensus);
        SetFederationBlake2bAndRdts(consensus);
        SetFederationTaprootDeployment(consensus);
        consensus.powLimit = uint256{"000000ffff000000000000000000000000000000000000000000000000000000"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        // Dummy MAIN identity; not launched. Placeholder; replaced at announcement.
        pchMessageStart[0] = 0x00; // dummy MAIN; not launched
        pchMessageStart[1] = 0x00;
        pchMessageStart[2] = 0x00;
        pchMessageStart[3] = 0x00;
        nDefaultPort = 4095; // dummy MAIN P2P; not launched
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 0;

        // Dummy MAIN; not launched. At announcement, Blake2b nBits should be
        // 100x Bitcoin genesis: 0x1d00ffff target / 100, compact 0x1c028f59.
        // Do not remine this placeholder until then.
        // nTime is LOCKTIME_THRESHOLD so timestamp-lock tests still mean timestamps.
        genesis = CreateGenesisBlock("UNLAUNCHED FederationCoin placeholder; not main", UnspendableGenesisScript(), LOCKTIME_THRESHOLD, 3586848, 0x1e00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"0000002df35a11022728c1c1e0eedc4fd2aa586ed18b5b8e959a1f305d8ffbe6"});
        assert(genesis.hashMerkleRoot == uint256{"afac624c7141d875152c8e8f74b7c6138b2ddf6fb8611f5c7d49518ce3f3447e"});

        vSeeds.clear();
        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,36);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,16);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,164);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xFC, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xFC, 0xE4};

        bech32_hrp = "fcn";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
            }
        };

        m_assumeutxo_data = {
        };

        chainTxData = ChainTxData{
            .nTime    = 0,
            .tx_count = 0,
            .dTxRate  = 0,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        SetFederationBuriedBips(consensus);
        SetFederationBlake2bAndRdts(consensus);
        SetFederationTaprootDeployment(consensus);
        consensus.powLimit = uint256{"000000ffff000000000000000000000000000000000000000000000000000000"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xe3;
        pchMessageStart[2] = 0x1e;
        pchMessageStart[3] = 0xc3;
        nDefaultPort = 35333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 0;

        // Blake2b from height 1 inherits genesis nBits: Blake2bTargetShift is 0,
        // so GetNextWorkRequired does not change the compact target at Blake2bHeight.
        // Height 0 is still SHA256d (v1 header). Those bits live on genesis so Blake2b
        // matches Bitcoin launch difficulty (0x1d00ffff) without a second policy.
        genesis = CreateGenesisBlock("09/Sep/2026 FederationCoin testnet3: time is the unit, not the state", UnspendableGenesisScript(), 1788912001, 926009097, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"000000007b820d7dd6173e5c91ac6c5851a5a914bbe228d20b99e94cdd2d7733"});
        assert(genesis.hashMerkleRoot == uint256{"657a6ec8479f3691139773b02986e6941fb1a7e951e30b8e3676d062e78b0e9f"});

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("seed.testnet.federationcoin.org.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,197);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0xFC, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0xFC, 0xE4};

        bech32_hrp = "tfcn";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
            }
        };

        m_assumeutxo_data = {
        };

        chainTxData = ChainTxData{
            .nTime    = 0,
            .tx_count = 0,
            .dTxRate  = 0,
        };
    }
};

/**
 * Testnet (v4): public test network which is reset from time to time.
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        SetFederationBuriedBips(consensus);
        SetFederationBlake2bAndRdts(consensus);
        SetFederationTaprootDeployment(consensus);
        consensus.powLimit = uint256{"000000ffff000000000000000000000000000000000000000000000000000000"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xe4;
        pchMessageStart[2] = 0x1e;
        pchMessageStart[3] = 0xc4;
        nDefaultPort = 45333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 0;

        // Same nBits as testnet3: Blake2b inherits genesis compact bits (shift 0).
        genesis = CreateGenesisBlock("09/Sep/2026 FederationCoin testnet4: time is the unit, not the state", UnspendableGenesisScript(), 1788912002, 5926862, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"00000000518588d27956912b3e6c5a310067c1d43a95290bd84b5d4f732d1622"});
        assert(genesis.hashMerkleRoot == uint256{"46ebc78e97f6f0293a7e542d61da1ae9928204cc8e09721326cc92d6ae3d0e31"});

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,197);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0xFC, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0xFC, 0xE4};

        bech32_hrp = "tfcn";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
            }
        };

        m_assumeutxo_data = {
        };

        chainTxData = ChainTxData{
            .nTime    = 0,
            .tx_count = 0,
            .dTxRate  = 0,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        if (!options.challenge) {
            bin = {0x51}; // OP_TRUE: experimental signet, anyone can mine
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000;
        SetFederationBuriedBips(consensus);
        SetFederationBlake2bAndRdts(consensus);
        SetFederationTaprootDeployment(consensus);
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = options.pow_target_spacing;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.powLimit = uint256{"00000377ae000000000000000000000000000000000000000000000000000000"};
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 26333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock("09/Sep/2026 FederationCoin signet: time is the unit, not the state", UnspendableGenesisScript(), 1788912003, 7283474, 0x1e0377ae, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"000001157c04349393694e070e3fc59e8b18e57dc13bea6d5568a1849bd2c4a6"});
        assert(genesis.hashMerkleRoot == uint256{"10a567d0a1c45207d19024fac1a955e8021be0cda560fe31bd3bda5547d3d7c5"});

        m_assumeutxo_data = {
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,197);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0xFC, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0xFC, 0xE4};

        bech32_hrp = "tfcn";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        SetFederationBuriedBips(consensus);
        SetFederationBlake2bAndRdts(consensus);
        SetFederationTaprootDeployment(consensus);
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xe7;
        pchMessageStart[2] = 0x1e;
        pchMessageStart[3] = 0xc7;
        nDefaultPort = 25444;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_BLAKE2B:
                consensus.Blake2bHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        if (opts.blake2b_headline) {
            consensus.Blake2bHeadline = *opts.blake2b_headline;
        }

        // Optionally schedule the RDTS deployment (see -rdtsexpiry). RDTS
        // activates at the BLAKE2b fork height scheduled above; only the
        // expiry is separately settable, as on mainnet. Left unscheduled by
        // default, so regtest behaviour is unchanged.
        if (opts.rdts_expiry_time) {
            consensus.RdtsExpiryTime = *opts.rdts_expiry_time;
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
            consensus.vDeployments[deployment_pos].max_activation_height = version_bits_params.max_activation_height;
            consensus.vDeployments[deployment_pos].active_duration = version_bits_params.active_duration;
            // Validated here rather than in src/chainparams.cpp because nMinerConfirmationWindow is not yet available at parse time
            if (version_bits_params.active_duration != std::numeric_limits<int>::max() && version_bits_params.active_duration % consensus.nMinerConfirmationWindow != 0) {
                throw std::runtime_error(strprintf("active_duration (%d) must be a multiple of nMinerConfirmationWindow (%d)", version_bits_params.active_duration, consensus.nMinerConfirmationWindow));
            }
            consensus.vDeployments[deployment_pos].threshold = version_bits_params.threshold;
        }

        genesis = CreateGenesisBlock("09/Sep/2026 FederationCoin regtest: time is the unit, not the state", UnspendableGenesisScript(), 1788912004, 0, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"7540675e579ae63ff4628473bab9e7098d1e30d24c344f59855785989677dbc1"});
        assert(genesis.hashMerkleRoot == uint256{"aa24b4644d39b44ed8cc3f1957b070b26d85c3c04f03833487f915dd71a9f609"});

        vFixedSeeds.clear();
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
            }
        };

        m_assumeutxo_data = {
            {
                .height = 110,
                .hash_serialized = AssumeutxoHash{uint256{"289909189a8e60dd0759ca4fa222eeaa7c109bee1d307213bec1be6dbe0202d2"}},
                .m_chain_tx_count = 111,
                .blockhash = consteval_ctor(uint256{"5d195e9d96c551feddabec553524177c0650669c6ae046798d9b24e9191c9990"}),
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,197);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0xFC, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0xFC, 0xE4};

        bech32_hrp = "fcnrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, testnet4_msg)) {
        return ChainType::TESTNET4;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
