// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/block_limits.h>
#include <consensus/checked_arith.h>
#include <consensus/epoch_watermark.h>
#include <consensus/flex_weight.h>
#include <consensus/spend_kind_weight.h>
#include <script/modern_sig.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <variant>

#include <limits>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(flex_weight_tests, BasicTestingSetup)

static void ExpectProduct(uint64_t a, uint64_t b, uint64_t hi, uint64_t lo)
{
    const Consensus::WideProduct got{Consensus::Mul128(a, b)};
    BOOST_CHECK_EQUAL(got.hi, hi);
    BOOST_CHECK_EQUAL(got.lo, lo);
#if defined(__SIZEOF_INT128__)
    const unsigned __int128 prod{static_cast<unsigned __int128>(a) * b};
    BOOST_CHECK_EQUAL(got.hi, static_cast<uint64_t>(prod >> 64));
    BOOST_CHECK_EQUAL(got.lo, static_cast<uint64_t>(prod));
#endif
}

BOOST_AUTO_TEST_CASE(named_bounds)
{
    BOOST_CHECK_EQUAL(Consensus::MIN_FLEX_BLOCK_WEIGHT, 2400000ULL);
    BOOST_CHECK_EQUAL(Consensus::MAX_FLEX_BLOCK_WEIGHT, 87841638446235ULL);
    BOOST_CHECK_EQUAL(Consensus::MAX_FLEX_BLOCK_WEIGHT, std::numeric_limits<uint64_t>::max() / 210000);
    BOOST_CHECK_EQUAL(Consensus::FULL_FIT_BUFFER_WEIGHT, 64ULL);
    BOOST_CHECK_EQUAL(Consensus::GROW_CAP_NUM, 28ULL);
    BOOST_CHECK_EQUAL(Consensus::GROW_CAP_DEN, 25ULL);
}

BOOST_AUTO_TEST_CASE(simple_payment_weights)
{
    BOOST_CHECK_EQUAL(Consensus::SPEND_KIND_ROWS.size(), 3U);
    const std::optional<uint64_t> native{Consensus::SimplePaymentWeight(Consensus::SPEND_KIND_ROWS[0])};
    const std::optional<uint64_t> dilithium44{Consensus::SimplePaymentWeight(Consensus::SPEND_KIND_ROWS[1])};
    const std::optional<uint64_t> dilithium87{Consensus::SimplePaymentWeight(Consensus::SPEND_KIND_ROWS[2])};
    BOOST_REQUIRE(native && dilithium44 && dilithium87);
    BOOST_CHECK_EQUAL(*native, 439ULL);
    BOOST_CHECK_EQUAL(*dilithium44, 4125ULL);
    BOOST_CHECK_EQUAL(*dilithium87, 7612ULL);
    BOOST_CHECK_EQUAL(BuildModernSingle(uint256::ZERO, ALGO_DILITHIUM, PARAM_DILITHIUM_44).size(),
                      Consensus::SPEND_KIND_ROWS[1].spk_len);
    BOOST_CHECK_EQUAL(BuildModernSingle(uint256::ZERO, ALGO_DILITHIUM, PARAM_DILITHIUM_87).size(),
                      Consensus::SPEND_KIND_ROWS[2].spk_len);
    const std::optional<uint64_t> smallest{Consensus::SmallestSimplePaymentWeight(0)};
    BOOST_REQUIRE(smallest);
    BOOST_CHECK_EQUAL(*smallest, 439ULL);
    BOOST_CHECK(!Consensus::SmallestSimplePaymentWeight(-1));
}

BOOST_AUTO_TEST_CASE(mul128_table)
{
    const uint64_t u32max{std::numeric_limits<uint32_t>::max()};
    const uint64_t u64max{std::numeric_limits<uint64_t>::max()};
    ExpectProduct(0, 0, 0, 0);
    ExpectProduct(0, u64max, 0, 0);
    ExpectProduct(1, 1, 0, 1);
    ExpectProduct(u32max, u32max, 0, 18446744065119617025ULL);
    ExpectProduct(uint64_t{u32max} + 1, uint64_t{u32max} + 1, 1, 0);
    ExpectProduct(u32max, uint64_t{u32max} + 1, 0, 18446744069414584320ULL);
    ExpectProduct(u64max, 1, 0, u64max);
    ExpectProduct(u64max, u64max, 18446744073709551614ULL, 1);
    ExpectProduct(u64max, u64max - 1, 18446744073709551613ULL, 2);
    // All three low halves are large; mid34 carries.
    ExpectProduct(0x1FFFFFFFFULL, 0x1FFFFFFFFULL, 3, 18446744056529682433ULL);
    ExpectProduct(Consensus::MAX_FLEX_BLOCK_WEIGHT, 210000, 0, 18446744073709350000ULL);
}

BOOST_AUTO_TEST_CASE(wrapping_u64)
{
    const uint64_t max64{std::numeric_limits<uint64_t>::max()};
    BOOST_CHECK_EQUAL(Consensus::WrappingAddU64(0, 0), 0);
    BOOST_CHECK_EQUAL(Consensus::WrappingAddU64(1, 2), 3);
    BOOST_CHECK_EQUAL(Consensus::WrappingAddU64(max64, 0), max64);
    BOOST_CHECK_EQUAL(Consensus::WrappingAddU64(max64, 1), 0);
    BOOST_CHECK_EQUAL(Consensus::WrappingAddU64(max64, 2), 1);
    BOOST_CHECK_EQUAL(Consensus::WrappingAddU64(15403900885539315214ULL, 10288079424817030725ULL),
                      7245236236646794323ULL);
    BOOST_CHECK_EQUAL(Consensus::WrappingSubU64(5, 3), 2);
    BOOST_CHECK_EQUAL(Consensus::WrappingSubU64(0, 0), 0);
    BOOST_CHECK_EQUAL(Consensus::WrappingSubU64(0, 1), max64);
    BOOST_CHECK_EQUAL(Consensus::WrappingSubU64(1, 2), max64);
}

BOOST_AUTO_TEST_CASE(mulge_sides)
{
    const uint64_t max64{std::numeric_limits<uint64_t>::max()};
    BOOST_CHECK(Consensus::MulGe(0, max64, 0, 1));
    BOOST_CHECK(Consensus::MulGe(0, max64, 0, max64));
    BOOST_CHECK(!Consensus::MulGe(0, max64, 1, 1));
    BOOST_CHECK(Consensus::MulGe(2, 3, 3, 2));
    BOOST_CHECK(Consensus::MulGe(3, 3, 2, 4));
    BOOST_CHECK(!Consensus::MulGe(2, 4, 3, 3));
    BOOST_CHECK(Consensus::MulGe(max64, max64, max64, max64));
    BOOST_CHECK(Consensus::MulGe(max64, max64, max64, max64 - 1));
    BOOST_CHECK(!Consensus::MulGe(max64, max64 - 1, max64, max64));
    BOOST_CHECK(Consensus::MulGe(max64, 2, max64, 1));
    BOOST_CHECK(!Consensus::MulGe(1, 1, max64, max64));
    BOOST_CHECK(Consensus::MulGe(5, 1, 4, 1));
    BOOST_CHECK(!Consensus::MulGe(4, 1, 5, 1));
}

BOOST_AUTO_TEST_CASE(grow_and_shrink)
{
    const Consensus::GrowCapResult even{Consensus::GrowCap(2400000)};
    const Consensus::Grew* even_grew{std::get_if<Consensus::Grew>(&even)};
    BOOST_REQUIRE(even_grew);
    BOOST_CHECK_EQUAL(even_grew->cap, 2688000ULL);

    const Consensus::GrowCapResult next{Consensus::GrowCap(2688000)};
    const Consensus::Grew* next_grew{std::get_if<Consensus::Grew>(&next)};
    BOOST_REQUIRE(next_grew);
    BOOST_CHECK_EQUAL(next_grew->cap, 3010560ULL);

    const Consensus::GrowCapResult remainder{Consensus::GrowCap(26)};
    const Consensus::Grew* remainder_grew{std::get_if<Consensus::Grew>(&remainder)};
    BOOST_REQUIRE(remainder_grew);
    BOOST_CHECK_EQUAL(remainder_grew->cap, 29ULL);

    const Consensus::GrowCapResult third{Consensus::GrowCap(3010560)};
    const Consensus::Grew* third_grew{std::get_if<Consensus::Grew>(&third)};
    BOOST_REQUIRE(third_grew);
    BOOST_CHECK_EQUAL(third_grew->cap, 3371827ULL);

    const Consensus::GrowCapResult ceiling{Consensus::GrowCap(Consensus::MAX_FLEX_BLOCK_WEIGHT)};
    BOOST_CHECK(std::holds_alternative<Consensus::AtCeiling>(ceiling));
    BOOST_CHECK_EQUAL(std::get<Consensus::AtCeiling>(ceiling).cap, Consensus::MAX_FLEX_BLOCK_WEIGHT);

    BOOST_CHECK_EQUAL(Consensus::ShrinkCap(2688000), 2400000ULL);
    BOOST_CHECK_EQUAL(Consensus::ShrinkCap(5400000), 2700000ULL);
    BOOST_CHECK_EQUAL(Consensus::ShrinkCap(5400001), 2700000ULL);
    BOOST_CHECK_EQUAL(Consensus::ShrinkCap(2400000), 2400000ULL);
    BOOST_CHECK_EQUAL(Consensus::ShrinkCap(5), 2400000ULL);
}

BOOST_AUTO_TEST_CASE(grow_does_not_wrap)
{
    const uint64_t too_wide{std::numeric_limits<uint64_t>::max() / Consensus::GROW_CAP_NUM + 1};
    const Consensus::GrowCapResult overflow{Consensus::GrowCap(too_wide)};
    BOOST_CHECK(std::holds_alternative<Consensus::MultiplyWouldOverflow>(overflow));
    BOOST_CHECK_EQUAL(Consensus::DecideNextCap(too_wide, /*pegged_blocks=*/210000, /*slack_blocks=*/0, /*interval=*/210000), too_wide);
}

BOOST_AUTO_TEST_CASE(pegged_and_slack_block)
{
    const uint64_t cap{2400000};
    BOOST_CHECK(Consensus::Pegged(cap, cap, 0));
    BOOST_CHECK(Consensus::Pegged(cap - 502, cap, 0));
    BOOST_CHECK(!Consensus::Pegged(cap - 503, cap, 0));
    BOOST_CHECK(!Consensus::Pegged(cap + 1, cap, 0));

    BOOST_CHECK(Consensus::Slack(479999, cap));
    BOOST_CHECK(!Consensus::Slack(480000, cap));
    BOOST_CHECK(!Consensus::Slack(cap - 502, cap));
}

BOOST_AUTO_TEST_CASE(four_fifths_counts)
{
    BOOST_CHECK(!Consensus::CountMeetsFourFifths(0, 210000));
    BOOST_CHECK(!Consensus::CountMeetsFourFifths(167999, 210000));
    BOOST_CHECK(Consensus::CountMeetsFourFifths(168000, 210000));
    BOOST_CHECK(Consensus::CountMeetsFourFifths(210000, 210000));
    BOOST_CHECK(!Consensus::CountMeetsFourFifths(119, 150));
    BOOST_CHECK(Consensus::CountMeetsFourFifths(120, 150));
    BOOST_CHECK(!Consensus::CountMeetsFourFifths(120, 0));
    BOOST_CHECK(!Consensus::CountMeetsFourFifths(120, -1));
}

BOOST_AUTO_TEST_CASE(unchanged_load_does_not_cycle)
{
    const uint64_t cap{3010560};
    const uint64_t weight{500000};
    BOOST_CHECK(Consensus::Slack(weight, cap));
    const uint64_t cut{Consensus::ShrinkCap(cap)};
    BOOST_CHECK_EQUAL(cut, 2400000ULL);
    BOOST_CHECK(!Consensus::Slack(weight, cut));
    BOOST_CHECK(!Consensus::Pegged(weight, cut, 0));

    Consensus::EpochWatermark held;
    for (int h{0}; h < 150; ++h) {
        held.AddBlock(weight, cut, h);
    }
    BOOST_CHECK_EQUAL(held.CapAfter(cut, 150), cut);

    const uint64_t floor_cap{2400000};
    const uint64_t full{floor_cap - 502};
    BOOST_CHECK(Consensus::Pegged(full, floor_cap, 0));
    const Consensus::GrowCapResult grown{Consensus::GrowCap(floor_cap)};
    const Consensus::Grew* grew{std::get_if<Consensus::Grew>(&grown)};
    BOOST_REQUIRE(grew);
    BOOST_CHECK(!Consensus::Pegged(full, grew->cap, 0));
    BOOST_CHECK(!Consensus::Slack(full, grew->cap));
}

BOOST_AUTO_TEST_CASE(watermark_epoch_boundary)
{
    Consensus::EpochWatermark mark;
    const uint64_t cap{2400000};
    const uint64_t full{cap - 502};
    const int interval{150};
    for (int h{0}; h < 120; ++h) {
        mark.AddBlock(full, cap, h);
    }
    BOOST_CHECK_EQUAL(mark.pegged_blocks, 120U);
    BOOST_CHECK_EQUAL(mark.slack_blocks, 0U);
    BOOST_CHECK_EQUAL(mark.CapAfter(cap, interval), 2688000ULL);
    BOOST_CHECK_EQUAL(Consensus::CapForBlock(cap, mark, 150, interval), 2688000ULL);
    BOOST_CHECK_EQUAL(Consensus::CapForBlock(cap, mark, 149, interval), cap);

    Consensus::EpochWatermark shy;
    for (int h{0}; h < 119; ++h) {
        shy.AddBlock(full, cap, h);
    }
    BOOST_CHECK_EQUAL(shy.CapAfter(cap, interval), cap);

    Consensus::EpochWatermark quiet;
    for (int h{0}; h < 150; ++h) {
        quiet.AddBlock(1000, 2688000, h);
    }
    BOOST_CHECK_EQUAL(quiet.slack_blocks, 150U);
    BOOST_CHECK_EQUAL(quiet.CapAfter(2688000, interval), 2400000ULL);
    BOOST_CHECK_EQUAL(quiet.CapAfter(cap, interval), cap);
}

BOOST_AUTO_TEST_CASE(limits_follow_the_cap)
{
    const Consensus::BlockLimits floor{Consensus::LimitsForCap(2400000)};
    BOOST_CHECK_EQUAL(floor.weight_cap, 2400000ULL);
    BOOST_CHECK_EQUAL(floor.serialized_size, 2400000ULL);
    BOOST_CHECK_EQUAL(floor.block_message_bytes, floor.serialized_size);
    BOOST_CHECK(floor.serialized_size >= floor.weight_cap);
    BOOST_CHECK_EQUAL(floor.sigops_cost, 48000);
    BOOST_CHECK_EQUAL(floor.standard_tx_sigops_cost, 9600);

    const Consensus::BlockLimits wide{Consensus::LimitsForCap(64000000)};
    BOOST_CHECK_EQUAL(wide.serialized_size, 64000000ULL);
    BOOST_CHECK(wide.serialized_size >= wide.weight_cap);
    BOOST_CHECK_EQUAL(wide.sigops_cost, 1280000);
    BOOST_CHECK_EQUAL(wide.standard_tx_sigops_cost, 256000);
    BOOST_CHECK(wide.max_outputs > floor.max_outputs);
    BOOST_CHECK(wide.max_transactions > floor.max_transactions);
    BOOST_CHECK(wide.compact_tx_count > floor.compact_tx_count);
}

BOOST_AUTO_TEST_CASE(admit_weight_for_window)
{
    BOOST_CHECK_EQUAL(Consensus::BLOCK_MESSAGE_ADMIT_WINDOW, 1024U);
    const Consensus::EpochWatermark empty{};
    const uint64_t floor{Consensus::MIN_FLEX_BLOCK_WEIGHT};
    // MAIN / testnet: a 1024 window from genesis never reaches 210000.
    BOOST_CHECK_EQUAL(Consensus::AdmitWeightForWindow(floor, empty, 0, 210000, 1024), floor);
    // One remaining MAIN boundary in the window is one GrowCap.
    BOOST_CHECK_EQUAL(Consensus::AdmitWeightForWindow(floor, empty, 209000, 210000, 1024), 2688000ULL);
    BOOST_CHECK_EQUAL(Consensus::AdmitWeightForWindow(floor, empty, 209999, 210000, 1024), floor);

    Consensus::EpochWatermark pegged;
    for (int h{0}; h < 168000; ++h) {
        pegged.AddBlock(floor - 502, floor, h);
    }
    BOOST_CHECK_EQUAL(Consensus::AdmitWeightForWindow(floor, pegged, 209999, 210000, 1024), 2688000ULL);

    // Regtest interval 160: the next block may already grow, then five more
    // boundaries sit in a 1024 window. Admit is not "next cap only".
    BOOST_CHECK_EQUAL(Consensus::AdmitWeightForWindow(floor, empty, 0, 160, 160), 2688000ULL);
    BOOST_CHECK_EQUAL(Consensus::AdmitWeightForWindow(floor, empty, 0, 160, 1024), 4737173ULL);
    BOOST_CHECK_EQUAL(Consensus::AdmitWeightForWindow(floor, empty, 159, 160, 1024), 4737173ULL);
    BOOST_CHECK_GT(Consensus::LimitsForCap(4737173ULL).compact_tx_count,
                   Consensus::LimitsForCap(floor).compact_tx_count);
    BOOST_CHECK_GT(Consensus::LimitsForCap(4737173ULL).max_transactions,
                   Consensus::LimitsForCap(floor).max_transactions);
}

BOOST_AUTO_TEST_CASE(checked_arith_bounds)
{
    uint64_t sum{1};
    BOOST_CHECK(Consensus::CheckedAdd(0, 0, sum));
    BOOST_CHECK_EQUAL(sum, 0ULL);
    BOOST_CHECK(Consensus::CheckedAdd(std::numeric_limits<uint64_t>::max(), 0, sum));
    BOOST_CHECK_EQUAL(sum, std::numeric_limits<uint64_t>::max());
    const uint64_t unchanged{7};
    sum = unchanged;
    BOOST_CHECK(!Consensus::CheckedAdd(std::numeric_limits<uint64_t>::max(), 1, sum));
    BOOST_CHECK_EQUAL(sum, unchanged);

    uint64_t product{1};
    BOOST_CHECK(Consensus::CheckedMul(0, std::numeric_limits<uint64_t>::max(), product));
    BOOST_CHECK_EQUAL(product, 0ULL);
    BOOST_CHECK(Consensus::CheckedMul(std::numeric_limits<uint64_t>::max(), 1, product));
    BOOST_CHECK_EQUAL(product, std::numeric_limits<uint64_t>::max());
    product = unchanged;
    BOOST_CHECK(!Consensus::CheckedMul(std::numeric_limits<uint64_t>::max(), 2, product));
    BOOST_CHECK_EQUAL(product, unchanged);

    uint64_t quotient{9};
    BOOST_CHECK(Consensus::FloorDiv(10, 3, quotient));
    BOOST_CHECK_EQUAL(quotient, 3ULL);
    BOOST_CHECK_EQUAL(10 % 3, 1);
    quotient = unchanged;
    BOOST_CHECK(!Consensus::FloorDiv(10, 0, quotient));
    BOOST_CHECK_EQUAL(quotient, unchanged);

    int64_t signed_sum{1};
    BOOST_CHECK(Consensus::CheckedAddSigned(std::numeric_limits<int64_t>::max(), 0, signed_sum));
    BOOST_CHECK_EQUAL(signed_sum, std::numeric_limits<int64_t>::max());
    signed_sum = 4;
    BOOST_CHECK(!Consensus::CheckedAddSigned(std::numeric_limits<int64_t>::max(), 1, signed_sum));
    BOOST_CHECK_EQUAL(signed_sum, 4);
    BOOST_CHECK(Consensus::CheckedAddSigned(std::numeric_limits<int64_t>::min(), 0, signed_sum));
    signed_sum = 4;
    BOOST_CHECK(!Consensus::CheckedAddSigned(std::numeric_limits<int64_t>::min(), -1, signed_sum));
    BOOST_CHECK_EQUAL(signed_sum, 4);
}

BOOST_AUTO_TEST_CASE(worst_case_cap_at_height)
{
    BOOST_CHECK_EQUAL(Consensus::ApplyGrowCapTimes(2400000, 0), 2400000ULL);
    BOOST_CHECK_EQUAL(Consensus::ApplyGrowCapTimes(2400000, 1), 2688000ULL);
    BOOST_CHECK_EQUAL(Consensus::ApplyGrowCapTimes(2400000, 2), 3010560ULL);
    BOOST_CHECK_EQUAL(Consensus::ApplyGrowCapTimes(26, 1), 29ULL);
    BOOST_CHECK_EQUAL(Consensus::WorstCaseCapAtHeight(0, 210000), 2400000ULL);
    BOOST_CHECK_EQUAL(Consensus::WorstCaseCapAtHeight(-1, 210000), 2400000ULL);
    BOOST_CHECK_EQUAL(Consensus::WorstCaseCapAtHeight(1, 0), 2400000ULL);
    // 209999 / 210000 is 0 epochs (floor toward zero), so still MIN_FLEX.
    BOOST_CHECK_EQUAL(Consensus::WorstCaseCapAtHeight(209999, 210000), 2400000ULL);
    BOOST_CHECK_EQUAL(Consensus::WorstCaseCapAtHeight(210000, 210000), 2688000ULL);
    BOOST_CHECK_EQUAL(Consensus::WorstCaseCapAtHeight(210001, 210000), 2688000ULL);
    BOOST_CHECK_EQUAL(Consensus::WorstCaseCapAtHeight(420000, 210000), 3010560ULL);
    uint64_t grown_cap{Consensus::MIN_FLEX_BLOCK_WEIGHT};
    for (;;) {
        const Consensus::GrowCapResult grown{Consensus::GrowCap(grown_cap)};
        if (const Consensus::Grew* g = std::get_if<Consensus::Grew>(&grown)) {
            grown_cap = g->cap;
            continue;
        }
        break;
    }
    BOOST_CHECK_EQUAL(Consensus::ApplyGrowCapTimes(Consensus::MIN_FLEX_BLOCK_WEIGHT, std::numeric_limits<uint64_t>::max()), grown_cap);
    BOOST_CHECK_EQUAL(Consensus::WorstCaseCapAtHeight(std::numeric_limits<int>::max(), 1), grown_cap);
    BOOST_CHECK(grown_cap <= Consensus::MAX_FLEX_BLOCK_WEIGHT);
}

BOOST_AUTO_TEST_CASE(receive_weight_one_grow_of_slack)
{
    Consensus::SetBlockMessageAdmitWeight(Consensus::MIN_FLEX_BLOCK_WEIGHT);
    Consensus::SetHeaderMaxFlex(Consensus::MIN_FLEX_BLOCK_WEIGHT);
    BOOST_CHECK_EQUAL(Consensus::BlockMessageReceiveWeight(),
                      Consensus::ApplyGrowCapTimes(Consensus::MIN_FLEX_BLOCK_WEIGHT, 1));
    Consensus::SetHeaderMaxFlex(2688000);
    BOOST_CHECK_EQUAL(Consensus::BlockMessageReceiveWeight(),
                      Consensus::ApplyGrowCapTimes(2688000, 1));
    Consensus::SetHeaderMaxFlex(Consensus::MIN_FLEX_BLOCK_WEIGHT);
}

BOOST_AUTO_TEST_SUITE_END()
