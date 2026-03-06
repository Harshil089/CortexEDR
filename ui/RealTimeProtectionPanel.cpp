#include "RealTimeProtectionPanel.hpp"
#include "EDRBridge.hpp"
#include <QMessageBox>
#include <QHBoxLayout>
#include <QStyle>

RealTimeProtectionPanel::RealTimeProtectionPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
    refreshStatus();
}

void RealTimeProtectionPanel::setupUI()
{
    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(16);

    // ── Page header ──────────────────────────────────────────────────────────
    QLabel* pageTitle = new QLabel("Real-Time Protection");
    pageTitle->setObjectName("PageTitle");
    QFont tf("Segoe UI", 20, QFont::DemiBold);
    pageTitle->setFont(tf);

    QLabel* pageSub = new QLabel("Monitor and control real-time threat detection");
    pageSub->setObjectName("PageSubtitle");

    root->addWidget(pageTitle);
    root->addWidget(pageSub);
    root->addSpacing(4);

    // ── Protection status card ────────────────────────────────────────────────
    QFrame* statusCard = new QFrame();
    statusCard->setObjectName("Card");
    {
        QVBoxLayout* sl = new QVBoxLayout(statusCard);
        sl->setContentsMargins(24, 20, 24, 20);
        sl->setSpacing(10);

        statusLabel_ = new QLabel("Protection Disabled");
        QFont sf("Segoe UI", 18, QFont::Bold);
        statusLabel_->setFont(sf);
        statusLabel_->setStyleSheet("color: #f87171;");

        statusDescLabel_ = new QLabel("This endpoint is not being monitored for threats");
        statusDescLabel_->setObjectName("PageSubtitle");
        statusDescLabel_->setWordWrap(true);

        toggleBtn_ = new QPushButton("Enable Protection");
        toggleBtn_->setObjectName("PrimaryBtn");
        toggleBtn_->setFixedHeight(34);
        toggleBtn_->setFixedWidth(200);
        toggleBtn_->setCursor(Qt::PointingHandCursor);

        connect(toggleBtn_, &QPushButton::clicked,
                this, &RealTimeProtectionPanel::onToggleClicked);

        sl->addWidget(statusLabel_);
        sl->addWidget(statusDescLabel_);
        sl->addSpacing(6);
        sl->addWidget(toggleBtn_);
    }
    root->addWidget(statusCard);

    // ── Monitor status ────────────────────────────────────────────────────────
    QLabel* monTitle = new QLabel("MONITOR COMPONENTS");
    monTitle->setObjectName("SectionTitle");
    root->addSpacing(4);
    root->addWidget(monTitle);

    QFrame* monitorCard = new QFrame();
    monitorCard->setObjectName("Card");
    {
        QVBoxLayout* ml = new QVBoxLayout(monitorCard);
        ml->setContentsMargins(0, 0, 0, 0);
        ml->setSpacing(0);

        auto addSep = [&]() {
            QFrame* sep = new QFrame();
            sep->setObjectName("HRule");
            sep->setFrameShape(QFrame::HLine);
            sep->setFixedHeight(1);
            ml->addWidget(sep);
        };

        ml->addWidget(createMonitorRow("Process Monitor",
                                       "ETW Kernel Provider",
                                       procDot_, processMonitorStatus_));
        addSep();
        ml->addWidget(createMonitorRow("File System",
                                       "ReadDirectoryChangesW",
                                       fileDot_, fileSystemStatus_));
        addSep();
        ml->addWidget(createMonitorRow("Network Monitor",
                                       "IP Helper API (TCP/UDP)",
                                       netDot_, networkMonitorStatus_));
        addSep();
        ml->addWidget(createMonitorRow("Registry Monitor",
                                       "RegNotifyChangeKeyValue",
                                       regDot_, registryMonitorStatus_));
    }
    root->addWidget(monitorCard);

    // ── Warning notice ────────────────────────────────────────────────────────
    QFrame* noticeCard = new QFrame();
    noticeCard->setObjectName("CardWarning");
    {
        QHBoxLayout* nl = new QHBoxLayout(noticeCard);
        nl->setContentsMargins(20, 12, 20, 12);
        QLabel* noticeText = new QLabel(
            "Disabling protection leaves this endpoint unmonitored. "
            "Re-enable immediately after any maintenance tasks.");
        noticeText->setStyleSheet("color: #fbbf24; font-size: 12px;");
        noticeText->setWordWrap(true);
        nl->addWidget(noticeText);
    }
    root->addWidget(noticeCard);
    root->addStretch();
}

QFrame* RealTimeProtectionPanel::createMonitorRow(const QString& name,
                                                   const QString& method,
                                                   QLabel*& dot,
                                                   QLabel*& statusLabel)
{
    QFrame* row = new QFrame();
    QHBoxLayout* rl = new QHBoxLayout(row);
    rl->setContentsMargins(20, 12, 20, 12);
    rl->setSpacing(10);

    dot = new QLabel();
    dot->setObjectName("DotGray");

    QLabel* nameLabel = new QLabel(name);
    QFont nf("Segoe UI", 13);
    nameLabel->setFont(nf);
    nameLabel->setStyleSheet("color: rgba(255,255,255,0.85);");

    QLabel* methodLabel = new QLabel(method);
    methodLabel->setStyleSheet("color: rgba(255,255,255,0.25); font-size: 11px;");

    statusLabel = new QLabel("Inactive");
    statusLabel->setStyleSheet("color: rgba(255,255,255,0.25); font-size: 12px;");
    statusLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    statusLabel->setMinimumWidth(60);

    rl->addWidget(dot);
    rl->addWidget(nameLabel);
    rl->addSpacing(8);
    rl->addWidget(methodLabel, 1);
    rl->addWidget(statusLabel);

    return row;
}

// ─── Slots ────────────────────────────────────────────────────────────────────

void RealTimeProtectionPanel::onToggleClicked()
{
    if (bridge_->isProtectionActive()) {
        // Require confirmation before disabling
        auto reply = QMessageBox::warning(
            this,
            "Disable Real-Time Protection",
            "Disabling protection leaves this endpoint unmonitored during the period "
            "it remains off.\n\nContinue?",
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel);

        if (reply != QMessageBox::Yes)
            return;

        bridge_->disableRealTimeProtection();
    } else {
        bridge_->enableRealTimeProtection();
    }
    refreshStatus();
}

void RealTimeProtectionPanel::refreshStatus()
{
    updateUI(bridge_->isProtectionActive());
}

void RealTimeProtectionPanel::updateUI(bool active)
{
    auto setMonitor = [](QLabel* dot, QLabel* lbl, bool on) {
        dot->setObjectName(on ? "DotGreen" : "DotGray");
        dot->style()->unpolish(dot);
        dot->style()->polish(dot);
        lbl->setText(on ? "Active" : "Inactive");
        lbl->setStyleSheet(on
            ? "color: #4ade80; font-size: 12px; font-weight: 600;"
            : "color: rgba(255,255,255,0.25); font-size: 12px;");
    };

    if (active) {
        statusLabel_->setText("Protection Active");
        statusLabel_->setStyleSheet("color: #4ade80; font-size: 18px; font-weight: 700;");
        statusDescLabel_->setText("All monitors operational — endpoint is protected");
        toggleBtn_->setText("Disable Protection");
        toggleBtn_->setObjectName("DestructiveBtn");
        toggleBtn_->style()->unpolish(toggleBtn_);
        toggleBtn_->style()->polish(toggleBtn_);
    } else {
        statusLabel_->setText("Protection Disabled");
        statusLabel_->setStyleSheet("color: #f87171; font-size: 18px; font-weight: 700;");
        statusDescLabel_->setText("This endpoint is not being monitored for threats");
        toggleBtn_->setText("Enable Protection");
        toggleBtn_->setObjectName("PrimaryBtn");
        toggleBtn_->style()->unpolish(toggleBtn_);
        toggleBtn_->style()->polish(toggleBtn_);
    }

    setMonitor(procDot_, processMonitorStatus_, active && bridge_->isProcessMonitorActive());
    setMonitor(fileDot_, fileSystemStatus_,     active && bridge_->isFileSystemHookActive());
    setMonitor(netDot_,  networkMonitorStatus_,  active && bridge_->isNetworkMonitorActive());
    setMonitor(regDot_,  registryMonitorStatus_, active && bridge_->isRegistryMonitorActive());
}
