#include "DashboardPanel.hpp"
#include "EDRBridge.hpp"
#include <QStyle>

DashboardPanel::DashboardPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();

    refreshTimer_ = new QTimer(this);
    connect(refreshTimer_, &QTimer::timeout, this, &DashboardPanel::refreshStatus);
    refreshTimer_->start(3000);

    refreshStatus();
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

static QFrame* makeDivider()
{
    QFrame* line = new QFrame();
    line->setObjectName("HRule");
    line->setFrameShape(QFrame::HLine);
    line->setFixedHeight(1);
    return line;
}

static QLabel* makeLabel(const QString& text, const QString& objectName,
                         int ptSize = 0, int weight = QFont::Normal)
{
    QLabel* l = new QLabel(text);
    l->setObjectName(objectName);
    if (ptSize > 0 || weight != QFont::Normal) {
        QFont f("Segoe UI", ptSize > 0 ? ptSize : -1, weight);
        l->setFont(f);
    }
    return l;
}

// ─── UI Setup ────────────────────────────────────────────────────────────────

void DashboardPanel::setupUI()
{
    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(20);

    // ── Page header ──────────────────────────────────────────────────────────
    QHBoxLayout* headerRow = new QHBoxLayout();
    headerRow->setSpacing(0);

    QVBoxLayout* titleCol = new QVBoxLayout();
    titleCol->setSpacing(2);

    QLabel* pageTitle = makeLabel("Dashboard", "PageTitle", 20, QFont::DemiBold);
    QLabel* pageSub   = makeLabel("System protection overview", "PageSubtitle");
    titleCol->addWidget(pageTitle);
    titleCol->addWidget(pageSub);

    quickScanBtn_ = new QPushButton("Run Quick Scan");
    quickScanBtn_->setObjectName("PrimaryBtn");
    quickScanBtn_->setFixedHeight(34);
    quickScanBtn_->setCursor(Qt::PointingHandCursor);
    connect(quickScanBtn_, &QPushButton::clicked, this, [this]() {
        emit quickScanRequested();
    });

    // Backend indicator (right of header)
    connectionIndicator_ = new QLabel();
    connectionIndicator_->setObjectName("DotRed");
    connectionLabel_ = new QLabel("Backend: Offline");
    connectionLabel_->setObjectName("SidebarFooterLabel");
    connectionLabel_->setStyleSheet("color: #f87171; font-size: 11px;");

    QHBoxLayout* connChip = new QHBoxLayout();
    connChip->setSpacing(6);
    connChip->addWidget(connectionIndicator_);
    connChip->addWidget(connectionLabel_);

    headerRow->addLayout(titleCol);
    headerRow->addStretch();
    headerRow->addLayout(connChip);
    headerRow->addSpacing(16);
    headerRow->addWidget(quickScanBtn_);

    root->addLayout(headerRow);

    // ── Status cards (2 × 2 grid) ────────────────────────────────────────────
    QGridLayout* grid = new QGridLayout();
    grid->setSpacing(14);
    grid->setColumnStretch(0, 1);
    grid->setColumnStretch(1, 1);

    // Card: Protection Status
    protectionCard_ = new QFrame();
    protectionCard_->setObjectName("Card");
    {
        QVBoxLayout* cl = new QVBoxLayout(protectionCard_);
        cl->setContentsMargins(20, 18, 20, 18);
        cl->setSpacing(6);

        QLabel* lbl = makeLabel("PROTECTION STATUS", "CardMetricLabel");
        protectionStatusLabel_ = new QLabel("Inactive");
        protectionStatusLabel_->setObjectName("CardMetricValueRed");
        QFont vf("Segoe UI", 22, QFont::Bold);
        protectionStatusLabel_->setFont(vf);

        cl->addWidget(lbl);
        cl->addWidget(protectionStatusLabel_);
        cl->addStretch();
    }
    protectionCard_->setMinimumHeight(110);

    // Card: Last Scan
    lastScanCard_ = new QFrame();
    lastScanCard_->setObjectName("Card");
    {
        QVBoxLayout* cl = new QVBoxLayout(lastScanCard_);
        cl->setContentsMargins(20, 18, 20, 18);
        cl->setSpacing(6);

        QLabel* lbl = makeLabel("LAST SCAN", "CardMetricLabel");
        lastScanLabel_ = new QLabel("Never");
        lastScanLabel_->setObjectName("CardMetricValue");
        QFont vf("Segoe UI", 16, QFont::Bold);
        lastScanLabel_->setFont(vf);
        lastScanLabel_->setWordWrap(true);

        cl->addWidget(lbl);
        cl->addWidget(lastScanLabel_);
        cl->addStretch();
    }
    lastScanCard_->setMinimumHeight(110);

    // Card: Threats Detected
    threatsCard_ = new QFrame();
    threatsCard_->setObjectName("Card");
    {
        QVBoxLayout* cl = new QVBoxLayout(threatsCard_);
        cl->setContentsMargins(20, 18, 20, 18);
        cl->setSpacing(6);

        QLabel* lbl = makeLabel("THREATS DETECTED", "CardMetricLabel");
        threatsLabel_ = new QLabel("0");
        threatsLabel_->setObjectName("CardMetricValueGreen");
        QFont vf("Segoe UI", 28, QFont::Bold);
        threatsLabel_->setFont(vf);

        cl->addWidget(lbl);
        cl->addWidget(threatsLabel_);
        cl->addStretch();
    }
    threatsCard_->setMinimumHeight(110);

    // Card: System Health
    healthCard_ = new QFrame();
    healthCard_->setObjectName("Card");
    {
        QVBoxLayout* cl = new QVBoxLayout(healthCard_);
        cl->setContentsMargins(20, 18, 20, 18);
        cl->setSpacing(6);

        QLabel* lbl = makeLabel("SYSTEM HEALTH", "CardMetricLabel");

        QHBoxLayout* healthRow = new QHBoxLayout();
        healthRow->setSpacing(8);
        healthIndicator_ = new QLabel();
        healthIndicator_->setObjectName("DotGray");
        healthLabel_ = new QLabel("Unknown");
        healthLabel_->setObjectName("CardMetricValue");
        QFont vf("Segoe UI", 18, QFont::Bold);
        healthLabel_->setFont(vf);
        healthRow->addWidget(healthIndicator_);
        healthRow->addWidget(healthLabel_);
        healthRow->addStretch();

        cl->addWidget(lbl);
        cl->addLayout(healthRow);
        cl->addStretch();
    }
    healthCard_->setMinimumHeight(110);

    grid->addWidget(protectionCard_, 0, 0);
    grid->addWidget(lastScanCard_,   0, 1);
    grid->addWidget(threatsCard_,    1, 0);
    grid->addWidget(healthCard_,     1, 1);

    root->addLayout(grid);

    // ── Monitor status ────────────────────────────────────────────────────────
    QLabel* monitorSectionTitle = makeLabel("MONITOR STATUS", "SectionTitle");
    root->addSpacing(4);
    root->addWidget(monitorSectionTitle);

    QFrame* monitorCard = new QFrame();
    monitorCard->setObjectName("Card");
    {
        QVBoxLayout* ml = new QVBoxLayout(monitorCard);
        ml->setContentsMargins(0, 0, 0, 0);
        ml->setSpacing(0);

        struct MonRow { const char* name; const char* method; QLabel** dot; QLabel** lbl; };
        MonRow rows[] = {
            { "Process Monitor",  "ETW Kernel Provider",         &procDot_,   &procStatus_    },
            { "File System",      "ReadDirectoryChangesW",        &fileDot_,   &fileStatus_    },
            { "Network Monitor",  "IP Helper API (TCP/UDP)",      &netDot_,    &netStatus_     },
            { "Registry Monitor", "RegNotifyChangeKeyValue",      &regDot_,    &regStatus_     },
        };

        for (int i = 0; i < 4; ++i) {
            if (i > 0) ml->addWidget(makeDivider());

            QFrame* row = new QFrame();
            QHBoxLayout* rl = new QHBoxLayout(row);
            rl->setContentsMargins(20, 12, 20, 12);
            rl->setSpacing(10);

            QLabel* dot = new QLabel();
            dot->setObjectName("DotGray");
            *rows[i].dot = dot;

            QLabel* name = makeLabel(rows[i].name, "", 13);
            name->setStyleSheet("color: rgba(255,255,255,0.85);");

            QLabel* method = makeLabel(rows[i].method, "");
            method->setStyleSheet("color: rgba(255,255,255,0.25); font-size: 11px;");

            QLabel* status = new QLabel("Inactive");
            status->setStyleSheet("color: rgba(255,255,255,0.25); font-size: 12px;");
            status->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            *rows[i].lbl = status;

            rl->addWidget(dot);
            rl->addWidget(name);
            rl->addSpacing(8);
            rl->addWidget(method, 1);
            rl->addWidget(status);
            ml->addWidget(row);
        }
    }
    root->addWidget(monitorCard);

    // ── Incident summary ──────────────────────────────────────────────────────
    QLabel* incidentSectionTitle = makeLabel("INCIDENT SUMMARY", "SectionTitle");
    root->addSpacing(4);
    root->addWidget(incidentSectionTitle);

    incidentCard_ = new QFrame();
    incidentCard_->setObjectName("Card");
    {
        QHBoxLayout* il = new QHBoxLayout(incidentCard_);
        il->setContentsMargins(20, 14, 20, 14);
        il->setSpacing(24);

        activeIncidentsLabel_  = makeLabel("Active: 0",   "", 13, QFont::DemiBold);
        totalIncidentsLabel_   = makeLabel("Total: 0",    "", 13);
        totalIncidentsLabel_->setStyleSheet("color: rgba(255,255,255,0.35);");

        il->addWidget(activeIncidentsLabel_);
        il->addWidget(makeDivider());  // reuse — will be vertical-ish via stretch
        il->addWidget(totalIncidentsLabel_);
        il->addStretch();
    }

    root->addWidget(incidentCard_);
    root->addStretch();
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

void DashboardPanel::refreshStatus()
{
    // Backend connection
    bool connected = bridge_->isBackendConnected();
    connectionIndicator_->setObjectName(connected ? "DotGreen" : "DotRed");
    connectionIndicator_->style()->unpolish(connectionIndicator_);
    connectionIndicator_->style()->polish(connectionIndicator_);
    connectionLabel_->setText(connected ? "Backend: Connected" : "Backend: Offline");
    connectionLabel_->setStyleSheet(connected
        ? "color: #4ade80; font-size: 11px;"
        : "color: #f87171; font-size: 11px;");

    // Protection
    bool active = bridge_->isProtectionActive();
    protectionStatusLabel_->setText(active ? "Active" : "Inactive");
    protectionStatusLabel_->setObjectName(active ? "CardMetricValueGreen" : "CardMetricValueRed");
    protectionStatusLabel_->style()->unpolish(protectionStatusLabel_);
    protectionStatusLabel_->style()->polish(protectionStatusLabel_);

    // Change card left-border accent
    protectionCard_->setObjectName(active ? "CardProtected" : "CardDanger");
    protectionCard_->style()->unpolish(protectionCard_);
    protectionCard_->style()->polish(protectionCard_);

    // Last scan
    QDateTime lastScan = bridge_->lastScanTime();
    if (lastScan.isValid()) {
        qint64 secsAgo = lastScan.secsTo(QDateTime::currentDateTime());
        QString ago;
        if (secsAgo < 3600)
            ago = QString("%1 min ago").arg(secsAgo / 60);
        else if (secsAgo < 86400)
            ago = QString("%1 hr ago").arg(secsAgo / 3600);
        else
            ago = lastScan.toString("yyyy-MM-dd");
        lastScanLabel_->setText(ago);
    } else {
        lastScanLabel_->setText("Never");
    }

    // Threats
    int threats = bridge_->totalThreats();
    threatsLabel_->setText(QString::number(threats));
    threatsLabel_->setObjectName(threats > 0 ? "CardMetricValueRed" : "CardMetricValueGreen");
    threatsLabel_->style()->unpolish(threatsLabel_);
    threatsLabel_->style()->polish(threatsLabel_);
    threatsCard_->setObjectName(threats > 0 ? "CardDanger" : "Card");
    threatsCard_->style()->unpolish(threatsCard_);
    threatsCard_->style()->polish(threatsCard_);

    // Health
    QString health = bridge_->systemHealthStatus();
    if (health == "Green") {
        healthLabel_->setText("Healthy");
        healthLabel_->setStyleSheet("color: #4ade80; font-size: 18px; font-weight: 700;");
        healthIndicator_->setObjectName("DotGreen");
    } else if (health == "Yellow") {
        healthLabel_->setText("At Risk");
        healthLabel_->setStyleSheet("color: #fbbf24; font-size: 18px; font-weight: 700;");
        healthIndicator_->setObjectName("DotAmber");
    } else {
        healthLabel_->setText("Unprotected");
        healthLabel_->setStyleSheet("color: #f87171; font-size: 18px; font-weight: 700;");
        healthIndicator_->setObjectName("DotRed");
    }
    healthIndicator_->style()->unpolish(healthIndicator_);
    healthIndicator_->style()->polish(healthIndicator_);

    // Monitor rows
    auto setMonitor = [](QLabel* dot, QLabel* lbl, bool on) {
        dot->setObjectName(on ? "DotGreen" : "DotGray");
        dot->style()->unpolish(dot);
        dot->style()->polish(dot);
        lbl->setText(on ? "Active" : "Inactive");
        lbl->setStyleSheet(on
            ? "color: #4ade80; font-size: 12px; font-weight: 600;"
            : "color: rgba(255,255,255,0.25); font-size: 12px;");
    };

    setMonitor(procDot_, procStatus_,   bridge_->isProcessMonitorActive());
    setMonitor(fileDot_, fileStatus_,   bridge_->isFileSystemHookActive());
    setMonitor(netDot_,  netStatus_,    bridge_->isNetworkMonitorActive());
    setMonitor(regDot_,  regStatus_,    bridge_->isRegistryMonitorActive());

    // Incidents
    int activeInc = bridge_->activeIncidentCount();
    int totalInc  = bridge_->totalIncidentCount();
    activeIncidentsLabel_->setText(QString("Active: %1").arg(activeInc));
    activeIncidentsLabel_->setStyleSheet(activeInc > 0
        ? "color: #fbbf24; font-size: 13px; font-weight: 600;"
        : "color: rgba(255,255,255,0.85); font-size: 13px; font-weight: 600;");
    totalIncidentsLabel_->setText(QString("Total: %1").arg(totalInc));
}
