// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/bitcoinunits_tests.h>

#include <qt/bitcoinunits.h>

void BitcoinUnitsTests::fromSetting()
{
    QCOMPARE(BitcoinUnits::FromSetting("0", BitcoinUnit::TOKEN), BitcoinUnit::COIN);
    QCOMPARE(BitcoinUnits::FromSetting("COIN", BitcoinUnit::TOKEN), BitcoinUnit::COIN);
    QCOMPARE(BitcoinUnits::FromSetting("1", BitcoinUnit::COIN), BitcoinUnit::TOKEN);
    QCOMPARE(BitcoinUnits::FromSetting("SEC", BitcoinUnit::COIN), BitcoinUnit::TOKEN);
    QCOMPARE(BitcoinUnits::FromSetting("TOKEN", BitcoinUnit::COIN), BitcoinUnit::TOKEN);
}
