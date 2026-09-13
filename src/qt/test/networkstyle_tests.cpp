// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/networkstyle_tests.h>

#include <qt/networkstyle.h>
#include <util/chaintype.h>

#include <memory>

#include <QColor>
#include <QImage>
#include <QPixmap>

namespace {
QRgb CornerPixel(const NetworkStyle* style)
{
    const QPixmap pix{style->getAppIcon().pixmap(64, 64)};
    const QImage img{pix.toImage()};
    return img.pixel(img.width() - 2, img.height() - 2);
}
} // namespace

void NetworkStyleTests::testnetBadgeDrawsNavyTriangle()
{
    std::unique_ptr<const NetworkStyle> style{NetworkStyle::instantiate(ChainType::TESTNET)};
    QVERIFY(style);
    QCOMPARE(QColor::fromRgb(CornerPixel(style.get())), QColor(0x00, 0x1f, 0x5c));
}

void NetworkStyleTests::mainHasNoNavyTriangle()
{
    std::unique_ptr<const NetworkStyle> style{NetworkStyle::instantiate(ChainType::MAIN)};
    QVERIFY(style);
    QVERIFY(QColor::fromRgb(CornerPixel(style.get())) != QColor(0x00, 0x1f, 0x5c));
}
