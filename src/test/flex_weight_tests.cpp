// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/epoch_watermark.h>
#include <consensus/flex_weight.h>
#include <test/util/setup_common.h>

#include <limits>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(flex_weight_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(named_bounds)
{
    BOOST_CHECK_EQUAL(Consensus::MIN_FLEX_BLOCK_WEIGHT, 2400000ULL);
    BOOST_CHECK_EQUAL(Consensus::MAX_FLEX_BLOCK_WEIGHT, 87841638446235ULL);
    BOOST_CHECK_EQUAL(Consensus::MAX_FLEX_BLOCK_WEIGHT, std::numeric_limits<uint64_t>::max() / 210000);
}

BOOST_AUTO_TEST_CASE(grow_and_shrink)
{
    BOOST_CHECK_EQUAL(Consensus::GrowCap(2400000), 3600000ULL);
    BOOST_CHECK_EQUAL(Consensus::GrowCap(3600000), 5400000ULL);
    BOOST_CHECK_EQUAL(Consensus::GrowCap(Consensus::MAX_FLEX_BLOCK_WEIGHT), Consensus::MAX_FLEX_BLOCK_WEIGHT);
    BOOST_CHECK_EQUAL(Consensus::ShrinkCap(3600000), 2400000ULL);
    BOOST_CHECK_EQUAL(Consensus::ShrinkCap(5400000), 2700000ULL);
    BOOST_CHECK_EQUAL(Consensus::ShrinkCap(2400000), 2400000ULL);
}

BOOST_AUTO_TEST_CASE(grow_refused_when_multiply_would_wrap)
{
    const uint64_t too_wide{std::numeric_limits<uint64_t>::max() / 3 + 1};
    BOOST_CHECK_EQUAL(Consensus::GrowCap(too_wide), too_wide);
}

BOOST_AUTO_TEST_CASE(hot_windows_and_mid_band)
{
    BOOST_CHECK(Consensus::ShouldGrow(13));
    BOOST_CHECK(Consensus::ShouldGrow(16));
    BOOST_CHECK(!Consensus::ShouldGrow(12));
    BOOST_CHECK(!Consensus::ShouldGrow(0));

    BOOST_CHECK(Consensus::ShouldShrink(/*epoch_weight=*/0, /*cap=*/3600000, /*interval=*/160));
    BOOST_CHECK(!Consensus::ShouldShrink(/*epoch_weight=*/720000, /*cap=*/2400000, /*interval=*/160));
    BOOST_CHECK(!Consensus::ShouldGrow(5) && !Consensus::ShouldShrink(800000, 2400000, 160));
    BOOST_CHECK(!(Consensus::ShouldGrow(13) && Consensus::ShouldShrink(13ULL * 1920000 * 10, 2400000, 160)));
}

BOOST_AUTO_TEST_CASE(unchanged_load_does_not_cycle)
{
    BOOST_CHECK(19 * 2 < 80);
    BOOST_CHECK(80 * 2 > 20 * 3);
    const uint64_t grown{3600000};
    const uint64_t interval{160};
    const uint64_t under20{(grown * interval) / 6};
    BOOST_CHECK(Consensus::ShouldShrink(under20, grown, static_cast<int>(interval)));
    const uint64_t after_shrink{Consensus::ShrinkCap(grown)};
    BOOST_CHECK(under20 * 100 / (after_shrink * interval) < 40);
    BOOST_CHECK(!Consensus::ShouldGrow(0));

    const uint64_t floor_cap{2400000};
    const uint64_t hot{floor_cap * 4 / 5};
    const uint64_t after_grow{Consensus::GrowCap(floor_cap)};
    BOOST_CHECK(hot * 100 / after_grow > 20);
    BOOST_CHECK(!Consensus::ShouldShrink(hot * interval, after_grow, static_cast<int>(interval)));
}

BOOST_AUTO_TEST_CASE(watermark_epoch_boundary)
{
    Consensus::EpochWatermark mark;
    const uint64_t cap{2400000};
    const int interval{160};
    for (int h{0}; h < 130; ++h) {
        mark.AddBlock(cap * 9 / 10, h, interval);
    }
    for (int h{130}; h < 160; ++h) {
        mark.AddBlock(cap / 10, h, interval);
    }
    BOOST_CHECK_EQUAL(mark.HotWindows(cap), 13);
    BOOST_CHECK_EQUAL(mark.CapAfter(cap, interval), 3600000ULL);
    BOOST_CHECK_EQUAL(Consensus::CapForBlock(cap, mark, 160, interval), 3600000ULL);
    BOOST_CHECK_EQUAL(Consensus::CapForBlock(cap, mark, 159, interval), cap);

    Consensus::EpochWatermark quiet;
    for (int h{0}; h < 160; ++h) {
        quiet.AddBlock(1000, h, interval);
    }
    BOOST_CHECK_EQUAL(quiet.CapAfter(3600000, interval), 2400000ULL);
    BOOST_CHECK_EQUAL(quiet.CapAfter(cap, interval), cap);
}

BOOST_AUTO_TEST_SUITE_END()
