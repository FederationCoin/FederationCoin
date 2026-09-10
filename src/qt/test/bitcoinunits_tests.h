// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_BITCOINUNITS_TESTS_H
#define BITCOIN_QT_TEST_BITCOINUNITS_TESTS_H

#include <QObject>
#include <QTest>

class BitcoinUnitsTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void fromSetting();
};

#endif // BITCOIN_QT_TEST_BITCOINUNITS_TESTS_H
