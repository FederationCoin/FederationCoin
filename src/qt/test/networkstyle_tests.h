// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_NETWORKSTYLE_TESTS_H
#define BITCOIN_QT_TEST_NETWORKSTYLE_TESTS_H

#include <QObject>
#include <QTest>

class NetworkStyleTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testnetBadgeDrawsNavyTriangle();
    void mainHasNoNavyTriangle();
};

#endif // BITCOIN_QT_TEST_NETWORKSTYLE_TESTS_H
