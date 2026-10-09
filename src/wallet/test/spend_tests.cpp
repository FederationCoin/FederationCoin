// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <key.h>
#include <outputtype.h>
#include <policy/fees.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

static COutPoint AddConfirmedProductCoin(CWallet& wallet, OutputType type, CAmount value)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CMutableTransaction tx;
    tx.vout.resize(1);
    tx.vout[0].nValue = value;
    tx.vout[0].scriptPubKey = GetScriptForDestination(*Assert(wallet.GetNewDestination(type, "")));
    const uint256 txid = tx.GetHash();
    wallet.mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(txid), std::forward_as_tuple(MakeTransactionRef(std::move(tx)), TxStateConfirmed{Params().GenesisBlock().GetHash(), /*height=*/0, /*index=*/0}));
    return COutPoint(Txid::FromUint256(txid), 0);
}

BOOST_AUTO_TEST_CASE(max_signed_input_size_uses_external_outpoint)
{
    const CKey key{GenerateRandomKey()};
    FillableSigningProvider provider;
    BOOST_REQUIRE(provider.AddKey(key));

    const CTxOut txout{COIN, GetScriptForDestination(WitnessV0KeyHash{key.GetPubKey()})};
    const COutPoint outpoint{Txid{}, 0};
    CCoinControl coin_control;
    coin_control.Select(outpoint).SetTxOut(txout);

    const int low_r{CalculateMaximumSignedInputSize(txout, COutPoint{}, &provider, /*can_grind_r=*/true, &coin_control)};
    const int high_r{CalculateMaximumSignedInputSize(txout, outpoint, &provider, /*can_grind_r=*/true, &coin_control)};
    // Unified sighash dummy signatures are fixed-width; grind-R does not shrink them.
    BOOST_CHECK_GT(low_r, 0);
    BOOST_CHECK_EQUAL(high_r, low_r);
}

BOOST_FIXTURE_TEST_CASE(SubtractFee, TestChain100Setup)
{
    auto wallet = CreateProductWallet(*m_node.chain);
    COutPoint coin_outpoint;
    {
        LOCK2(wallet->cs_wallet, ::cs_main);
        wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        const COutPoint funded = AddConfirmedProductCoin(*wallet, OutputType::DILITHIUM87, 50 * COIN);
        coin_outpoint = funded;
    }

    // Leftover that would be change is paid to the recipient when change is
    // Dilithium 87 (expensive to create and spend), not dropped to the miner.
    auto check_tx = [&](CAmount leftover_input_amount) {
        CRecipient recipient{ProductReceiveDest(*wallet, OutputType::DILITHIUM87), 50 * COIN - leftover_input_amount, /*subtract_fee=*/true};
        CCoinControl coin_control;
        coin_control.Select(coin_outpoint);
        coin_control.m_feerate.emplace(10000);
        coin_control.fOverrideFeeRate = true;
        coin_control.m_change_type = OutputType::DILITHIUM87;
        auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
        BOOST_CHECK(res);
        const auto& txr = *res;
        BOOST_CHECK_GT(txr.fee, 0);
        CAmount out_sum{0};
        for (const auto& out : txr.tx->vout) {
            out_sum += out.nValue;
            BOOST_CHECK_EQUAL(out.scriptPubKey.size(), 34U);
            BOOST_CHECK_EQUAL(out.scriptPubKey[0], OP_0);
        }
        BOOST_CHECK_EQUAL(out_sum + txr.fee, 50 * COIN);
        return txr.fee;
    };

    const CAmount fee{check_tx(0)};
    BOOST_CHECK_GT(fee, 0);
    BOOST_CHECK_GT(check_tx(123), 0);
    BOOST_CHECK_GT(check_tx(fee), 0);
    BOOST_CHECK_GT(check_tx(fee + 123), 0);
}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, TestChain100Setup)
{
    auto wallet = CreateProductWallet(*m_node.chain);
    LOCK(wallet->cs_wallet);
    wallet->SetLastBlockProcessed(300, uint256{});
    AddConfirmedProductCoin(*wallet, OutputType::DILITHIUM87, 50 * COIN);
    AddConfirmedProductCoin(*wallet, OutputType::DILITHIUM87, 50 * COIN);
    AddConfirmedProductCoin(*wallet, OutputType::DILITHIUM87, 50 * COIN);
    AddConfirmedProductCoin(*wallet, OutputType::DILITHIUM87, 50 * COIN);

    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();
    BOOST_REQUIRE_EQUAL(coins.size(), 4U);
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::DILITHIUM87, "dummy")),
                                           /*nAmount=*/299 * COIN, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));

    recipients[0].fSubtractFeeFromAmount = false;
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));
}

BOOST_AUTO_TEST_CASE(available_coins_separates_dilithium_kinds)
{
    auto wallet = CreateProductWallet(*m_node.chain);
    LOCK(wallet->cs_wallet);
    wallet->SetLastBlockProcessed(300, uint256{});
    AddConfirmedProductCoin(*wallet, OutputType::DILITHIUM87, COIN);
    AddConfirmedProductCoin(*wallet, OutputType::DILITHIUM44, COIN);
    AddConfirmedProductCoin(*wallet, OutputType::SECP, COIN);

    const CoinsResult coins{AvailableCoins(*wallet)};
    BOOST_CHECK_EQUAL(coins.coins.at(OutputType::DILITHIUM87).size(), 1U);
    BOOST_CHECK_EQUAL(coins.coins.at(OutputType::DILITHIUM44).size(), 1U);
    BOOST_CHECK_EQUAL(coins.coins.at(OutputType::SECP).size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
