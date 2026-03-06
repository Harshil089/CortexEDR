#include "AboutPanel.hpp"
#include <QHBoxLayout>
#include <QFrame>
#include <QFont>

AboutPanel::AboutPanel(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
}

void AboutPanel::setupUI()
{
    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(0);

    // ── Page title ───────────────────────────────────────────────────────────
    QLabel* pageTitle = new QLabel("About");
    pageTitle->setObjectName("PageTitle");
    QFont tf("Segoe UI", 20, QFont::DemiBold);
    pageTitle->setFont(tf);
    root->addWidget(pageTitle);
    root->addSpacing(20);

    // ── Product identity ─────────────────────────────────────────────────────
    QLabel* productName = new QLabel("CortexEDR");
    QFont pf("Segoe UI", 30, QFont::Bold);
    productName->setFont(pf);
    productName->setStyleSheet("color: #ffffff;");

    QLabel* productTagline = new QLabel("Endpoint Detection & Response");
    productTagline->setObjectName("PageSubtitle");

    root->addWidget(productName);
    root->addWidget(productTagline);
    root->addSpacing(24);

    // ── Info card ────────────────────────────────────────────────────────────
    QFrame* card = new QFrame();
    card->setObjectName("Card");
    QVBoxLayout* cl = new QVBoxLayout(card);
    cl->setContentsMargins(24, 20, 24, 20);
    cl->setSpacing(0);

    auto addRow = [&](const QString& label, const QString& value, bool lastInGroup = false) {
        QFrame* row = new QFrame();
        QHBoxLayout* rl = new QHBoxLayout(row);
        rl->setContentsMargins(0, 10, 0, 10);
        rl->setSpacing(16);

        QLabel* lbl = new QLabel(label);
        lbl->setStyleSheet("color: rgba(255,255,255,0.35); font-size: 12px;");
        lbl->setFixedWidth(160);

        QLabel* val = new QLabel(value);
        val->setStyleSheet("color: rgba(255,255,255,0.80); font-size: 12px;");
        val->setWordWrap(true);

        rl->addWidget(lbl);
        rl->addWidget(val, 1);
        cl->addWidget(row);

        if (!lastInGroup) {
            QFrame* sep = new QFrame();
            sep->setObjectName("HRule");
            sep->setFrameShape(QFrame::HLine);
            sep->setFixedHeight(1);
            cl->addWidget(sep);
        }
    };

    addRow("Version",           "1.0.0");
    addRow("Engine",            "CortexEDR Detection Engine");
    addRow("Architecture",      "x64  (Windows 10/11)");
    addRow("Build",             "C++20  /  Qt 6  /  MSVC 2022");
    addRow("License",           "Educational / Portfolio Project", true);

    // Section divider
    QFrame* groupSep = new QFrame();
    groupSep->setStyleSheet("background-color: rgba(255,255,255,0.06);");
    groupSep->setFixedHeight(1);
    cl->addWidget(groupSep);

    addRow("Process Monitor",   "ETW-based (Kernel Provider)");
    addRow("File Monitor",      "ReadDirectoryChangesW");
    addRow("Network Monitor",   "IP Helper API (TCP/UDP)");
    addRow("Registry Monitor",  "RegNotifyChangeKeyValue");
    addRow("Risk Engine",       "Weighted Scoring + Rules + Behavior");
    addRow("Incident Manager",  "State Machine + JSON Persistence", true);

    root->addWidget(card);
    root->addSpacing(16);

    // ── Footer ────────────────────────────────────────────────────────────────
    QLabel* footer = new QLabel(
        "Built with modern C++ practices: RAII, smart pointers, thread safety,\n"
        "event-driven architecture, and clean separation of concerns.");
    footer->setStyleSheet("color: rgba(255,255,255,0.15); font-size: 11px;");
    footer->setAlignment(Qt::AlignCenter);
    footer->setWordWrap(true);

    root->addWidget(footer);
    root->addStretch();
}
