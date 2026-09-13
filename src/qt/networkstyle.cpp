// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/networkstyle.h>

#include <qt/guiconstants.h>

#include <tinyformat.h>
#include <util/chaintype.h>

#include <algorithm>

#include <QApplication>
#include <QColor>
#include <QImage>
#include <QPainter>
#include <QPolygon>

static const struct {
    const ChainType networkId;
    const char *appName;
    const int iconColorHueShift;
    const int iconColorSaturationReduction;
    const bool testnetBadge;
} network_styles[] = {
    {ChainType::MAIN, QAPP_APP_NAME_DEFAULT, 0, 0, false},
    {ChainType::TESTNET, QAPP_APP_NAME_TESTNET, 0, 0, true},
    {ChainType::TESTNET4, QAPP_APP_NAME_TESTNET4, 0, 0, true},
    {ChainType::SIGNET, QAPP_APP_NAME_SIGNET, 35, 15, false},
    {ChainType::REGTEST, QAPP_APP_NAME_REGTEST, 160, 30, false},
};

// Keep in sync with src/qt/CMakeLists.txt TESTNET_TRIANGLE_* / TESTNET_NAVY.
static void OverlayTestnetTriangle(QImage& img)
{
    const int w = img.width();
    const int h = img.height();
    const int t = std::max(7, std::min(w, h) * 45 / 100);
    QPainter p(&img);
    p.setRenderHint(QPainter::Antialiasing, std::min(w, h) >= 48);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor(0x00, 0x1f, 0x5c));
    QPolygon tri;
    tri << QPoint(w - 1, h - 1) << QPoint(w - 1, h - 1 - t) << QPoint(w - 1 - t, h - 1);
    p.drawPolygon(tri);
}

// titleAddText needs to be const char* for tr()
NetworkStyle::NetworkStyle(const QString &_appName, const int iconColorHueShift, const int iconColorSaturationReduction, const char *_titleAddText, bool testnetBadge):
    m_colour_shift(std::make_pair(iconColorHueShift, iconColorSaturationReduction)),
    appName(_appName),
    titleAddText(qApp->translate("SplashScreen", _titleAddText))
{
    // load pixmap
    QPixmap pixmap(":/icons/bitcoin");
    const bool hue = iconColorHueShift != 0 && iconColorSaturationReduction != 0;

    if (hue || testnetBadge) {
        QImage img = pixmap.toImage().convertToFormat(QImage::Format_ARGB32);

        if (hue) {
            int h,s,l,a;

            // traverse though lines
            for(int y=0;y<img.height();y++)
            {
                QRgb *scL = reinterpret_cast< QRgb *>( img.scanLine( y ) );

                // loop through pixels
                for(int x=0;x<img.width();x++)
                {
                    // preserve alpha because QColor::getHsl doesn't return the alpha value
                    a = qAlpha(scL[x]);
                    QColor col(scL[x]);

                    // get hue value
                    col.getHsl(&h,&s,&l);

                    // rotate color on RGB color circle
                    h+=iconColorHueShift;

                    // change saturation value
                    if(s>iconColorSaturationReduction)
                    {
                        s -= iconColorSaturationReduction;
                    }
                    col.setHsl(h,s,l,a);

                    // set the pixel
                    scL[x] = col.rgba();
                }
            }
        }

        if (testnetBadge) {
            OverlayTestnetTriangle(img);
        }

        pixmap.convertFromImage(img);
    }

    appIcon = QIcon(pixmap);
    trayAndWindowIcon = QIcon(pixmap.scaled(QSize(256,256)));
}

QColor NetworkStyle::AdjustColour(QColor colour) const
{
    int h, s, l, a;

    // preserve alpha because QColor::getHsl doesn't return the alpha value
    a = colour.alpha();

    // get hue value
    colour.getHsl(&h, &s, &l);

    // rotate color on RGB color circle
    // 70° should end up with the typical "testnet" green
    h += m_colour_shift.first;

    // change saturation value
    if (s > m_colour_shift.second) {
        s -= m_colour_shift.second;
    }
    colour.setHsl(h, s, l, a);

    return colour;
}

const NetworkStyle* NetworkStyle::instantiate(const ChainType networkId)
{
    std::string titleAddText = networkId == ChainType::MAIN ? "" : strprintf("[%s]", ChainTypeToString(networkId));
    for (const auto& network_style : network_styles) {
        if (networkId == network_style.networkId) {
            return new NetworkStyle(
                    network_style.appName,
                    network_style.iconColorHueShift,
                    network_style.iconColorSaturationReduction,
                    titleAddText.c_str(),
                    network_style.testnetBadge);
        }
    }
    return nullptr;
}
