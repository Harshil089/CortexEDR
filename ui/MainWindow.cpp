#include "MainWindow.hpp"
#include "EDRBridge.hpp"
#include "DashboardPanel.hpp"
#include "QuickScanPanel.hpp"
#include "FullScanPanel.hpp"
#include "RealTimeProtectionPanel.hpp"
#include "SettingsPanel.hpp"
#include "QuarantinePanel.hpp"
#include "LogsPanel.hpp"
#include "AboutPanel.hpp"
#include <QCloseEvent>
#include <QApplication>
#include <QFile>
#include <QFont>
#include <QIcon>
#include <QPainter>
#include <QPixmap>
#include <QLabel>
#include <QFrame>
#include <QStatusBar>

MainWindow::MainWindow(EDRBridge* bridge, QWidget* parent)
    : QMainWindow(parent), bridge_(bridge)
{
    setWindowTitle("CortexEDR");
    setMinimumSize(1100, 700);
    resize(1280, 800);

    setupUI();
    setupStatusBar();
    setupSystemTray();
    applyStylesheet();

    // Threat notifications → tray
    connect(bridge_, &EDRBridge::threatNotification,
            this, &MainWindow::showThreatNotification);

    // Backend connection changes → status bar
    connect(bridge_, &EDRBridge::backendConnectionChanged,
            this, &MainWindow::onBackendConnectionChanged);

    // Initialize status bar state
    onBackendConnectionChanged(bridge_->isBackendConnected());
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUI()
{
    centralWidget_ = new QWidget(this);
    setCentralWidget(centralWidget_);

    mainLayout_ = new QHBoxLayout(centralWidget_);
    mainLayout_->setContentsMargins(0, 0, 0, 0);
    mainLayout_->setSpacing(0);

    setupSidebar();
    setupContentArea();

    mainLayout_->addWidget(sidebarWidget_);
    mainLayout_->addWidget(contentStack_, 1);
}

void MainWindow::setupSidebar()
{
    sidebarWidget_ = new QWidget();
    sidebarWidget_->setObjectName("Sidebar");
    sidebarWidget_->setFixedWidth(220);

    sidebarLayout_ = new QVBoxLayout(sidebarWidget_);
    sidebarLayout_->setContentsMargins(0, 0, 0, 0);
    sidebarLayout_->setSpacing(0);

    // Logo area — 64px, tight
    QFrame* logoArea = new QFrame();
    logoArea->setObjectName("LogoArea");
    logoArea->setFixedHeight(64);

    QVBoxLayout* logoLayout = new QVBoxLayout(logoArea);
    logoLayout->setContentsMargins(20, 12, 20, 12);
    logoLayout->setSpacing(2);

    logoLabel_ = new QLabel("CortexEDR");
    logoLabel_->setObjectName("LogoLabel");

    QLabel* tagline = new QLabel("Endpoint Detection & Response");
    tagline->setObjectName("LogoTagline");

    logoLayout->addWidget(logoLabel_);
    logoLayout->addWidget(tagline);

    // Navigation — text-only, no emojis
    navList_ = new QListWidget();
    navList_->setObjectName("NavList");
    navList_->setFrameShape(QFrame::NoFrame);
    navList_->setFocusPolicy(Qt::NoFocus);
    navList_->setIconSize(QSize(0, 0));

    const QStringList navItems = {
        "Dashboard",
        "Quick Scan",
        "Full System Scan",
        "Real-Time Protection",
        "Quarantine",
        "Event Logs",
        "Settings",
        "About"
    };

    for (const QString& item : navItems) {
        QListWidgetItem* li = new QListWidgetItem(item);
        li->setSizeHint(QSize(220, 40));
        navList_->addItem(li);
    }

    navList_->setCurrentRow(0);
    connect(navList_, &QListWidget::currentRowChanged,
            this, &MainWindow::onNavigationChanged);

    // Footer — backend status + version
    QFrame* footerFrame = new QFrame();
    footerFrame->setObjectName("SidebarFooter");
    QVBoxLayout* footerLayout = new QVBoxLayout(footerFrame);
    footerLayout->setContentsMargins(20, 10, 20, 12);
    footerLayout->setSpacing(4);

    backendStatusLabel_ = new QLabel("Backend: Offline");
    backendStatusLabel_->setObjectName("SidebarFooterLabel");

    QLabel* versionLabel = new QLabel("v1.0.0");
    versionLabel->setObjectName("VersionLabel");

    footerLayout->addWidget(backendStatusLabel_);
    footerLayout->addWidget(versionLabel);

    sidebarLayout_->addWidget(logoArea);
    sidebarLayout_->addWidget(navList_, 1);
    sidebarLayout_->addWidget(footerFrame);
}

void MainWindow::setupContentArea()
{
    contentStack_ = new QStackedWidget();

    dashboardPanel_  = new DashboardPanel(bridge_);
    quickScanPanel_  = new QuickScanPanel(bridge_);
    fullScanPanel_   = new FullScanPanel(bridge_);
    rtpPanel_        = new RealTimeProtectionPanel(bridge_);
    quarantinePanel_ = new QuarantinePanel(bridge_);
    logsPanel_       = new LogsPanel(bridge_);
    settingsPanel_   = new SettingsPanel(bridge_);
    aboutPanel_      = new AboutPanel();

    contentStack_->addWidget(dashboardPanel_);   // 0
    contentStack_->addWidget(quickScanPanel_);    // 1
    contentStack_->addWidget(fullScanPanel_);     // 2
    contentStack_->addWidget(rtpPanel_);          // 3
    contentStack_->addWidget(quarantinePanel_);   // 4
    contentStack_->addWidget(logsPanel_);         // 5
    contentStack_->addWidget(settingsPanel_);     // 6
    contentStack_->addWidget(aboutPanel_);        // 7

    // Dashboard quick scan → navigate and start
    connect(dashboardPanel_, &DashboardPanel::quickScanRequested, this, [this]() {
        navList_->setCurrentRow(1);
        quickScanPanel_->startScan();
    });

    // Scan signals → QuickScan panel
    connect(bridge_, &EDRBridge::scanProgressChanged,    quickScanPanel_, &QuickScanPanel::onProgressChanged);
    connect(bridge_, &EDRBridge::scanCurrentFileChanged, quickScanPanel_, &QuickScanPanel::onCurrentFileChanged);
    connect(bridge_, &EDRBridge::scanThreatDetected,     quickScanPanel_, &QuickScanPanel::onThreatDetected);
    connect(bridge_, &EDRBridge::scanFinished,           quickScanPanel_, &QuickScanPanel::onScanFinished);

    // Scan signals → FullScan panel
    connect(bridge_, &EDRBridge::scanProgressChanged,      fullScanPanel_, &FullScanPanel::onProgressChanged);
    connect(bridge_, &EDRBridge::scanCurrentFileChanged,   fullScanPanel_, &FullScanPanel::onCurrentFileChanged);
    connect(bridge_, &EDRBridge::scanThreatDetected,       fullScanPanel_, &FullScanPanel::onThreatDetected);
    connect(bridge_, &EDRBridge::scanFinished,             fullScanPanel_, &FullScanPanel::onScanFinished);
    connect(bridge_, &EDRBridge::scanEstimatedTimeChanged, fullScanPanel_, &FullScanPanel::onEstimatedTimeChanged);

    // Threat count → status bar
    connect(bridge_, &EDRBridge::threatCountChanged, this, &MainWindow::onThreatCountChanged);
}

void MainWindow::setupStatusBar()
{
    QStatusBar* bar = statusBar();
    bar->setSizeGripEnabled(false);

    globalStatusLabel_ = new QLabel("Initializing");
    globalStatusLabel_->setObjectName("StatusBarLabel");

    threatCountStatusLabel_ = new QLabel("Threats: 0");
    threatCountStatusLabel_->setObjectName("StatusBarLabel");

    incidentStatusLabel_ = new QLabel("Incidents: 0 active");
    incidentStatusLabel_->setObjectName("StatusBarLabel");

    backendStatusBarLabel_ = new QLabel("Backend: Offline");
    backendStatusBarLabel_->setObjectName("StatusBarLabel");

    // Soft dot separators instead of harsh lines
    auto makeSep = [&]() {
        QLabel* sep = new QLabel("\u00B7");
        sep->setStyleSheet("color: rgba(255,255,255,0.15); font-size: 14px; background-color: transparent;");
        return sep;
    };

    bar->addWidget(globalStatusLabel_);
    bar->addWidget(makeSep());
    bar->addWidget(threatCountStatusLabel_);
    bar->addWidget(makeSep());
    bar->addWidget(incidentStatusLabel_);
    bar->addPermanentWidget(backendStatusBarLabel_);
}

// ─── Navigation ───────────────────────────────────────────────────────────────

void MainWindow::onNavigationChanged(int index)
{
    contentStack_->setCurrentIndex(index);

    switch (index) {
        case 0: dashboardPanel_->refreshStatus();   break;
        case 3: rtpPanel_->refreshStatus();          break;
        case 4: quarantinePanel_->refreshTable();    break;
        case 5: logsPanel_->refreshLogs();           break;
        default: break;
    }
}

// ─── Status Bar Updates ───────────────────────────────────────────────────────

void MainWindow::onBackendConnectionChanged(bool connected)
{
    if (connected) {
        backendStatusLabel_->setText("Backend: Connected");
        backendStatusLabel_->setStyleSheet("color: #4ade80; font-size: 11px;");
        backendStatusBarLabel_->setText("Backend: Connected");
        backendStatusBarLabel_->setStyleSheet("color: #4ade80; font-size: 11px;");
        globalStatusLabel_->setText(bridge_->isProtectionActive() ? "Protected" : "Unprotected");
    } else {
        backendStatusLabel_->setText("Backend: Offline");
        backendStatusLabel_->setStyleSheet("color: #f87171; font-size: 11px;");
        backendStatusBarLabel_->setText("Backend: Offline");
        backendStatusBarLabel_->setStyleSheet("color: #f87171; font-size: 11px;");
        globalStatusLabel_->setText("Backend Offline");
        globalStatusLabel_->setStyleSheet("color: #fbbf24; font-size: 11px;");
    }
}

void MainWindow::onThreatCountChanged(int count)
{
    threatCountStatusLabel_->setText(QString("Threats: %1").arg(count));
    if (count > 0) {
        threatCountStatusLabel_->setStyleSheet("color: #f87171; font-size: 11px;");
        globalStatusLabel_->setText("At Risk");
        globalStatusLabel_->setStyleSheet("color: #f87171; font-size: 11px;");
    } else {
        threatCountStatusLabel_->setStyleSheet("color: rgba(255,255,255,0.35); font-size: 11px;");
    }

    int active = bridge_->activeIncidentCount();
    incidentStatusLabel_->setText(QString("Incidents: %1 active").arg(active));
    if (active > 0) {
        incidentStatusLabel_->setStyleSheet("color: #fbbf24; font-size: 11px;");
    } else {
        incidentStatusLabel_->setStyleSheet("color: rgba(255,255,255,0.35); font-size: 11px;");
    }
}

// ─── System Tray ─────────────────────────────────────────────────────────────

void MainWindow::setupSystemTray()
{
    trayIcon_ = new QSystemTrayIcon(this);
    trayIcon_->setToolTip("CortexEDR — Endpoint Detection & Response");

    // Simple programmatic icon — circle with 'C'
    QPixmap pixmap(32, 32);
    pixmap.fill(Qt::transparent);
    QPainter p(&pixmap);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(QColor("#4ade80"));
    p.setPen(Qt::NoPen);
    p.drawEllipse(2, 2, 28, 28);
    p.setPen(QPen(QColor("#0c0e14"), 2));
    QFont f("Segoe UI", 12, QFont::Bold);
    p.setFont(f);
    p.drawText(pixmap.rect(), Qt::AlignCenter, "C");
    p.end();
    trayIcon_->setIcon(QIcon(pixmap));

    trayMenu_ = new QMenu(this);
    trayMenu_->addAction("Show CortexEDR", this, [this]() {
        show(); raise(); activateWindow();
    });
    trayMenu_->addSeparator();
    trayMenu_->addAction("Quick Scan", this, [this]() {
        show();
        navList_->setCurrentRow(1);
        quickScanPanel_->startScan();
    });
    trayMenu_->addSeparator();
    trayMenu_->addAction("Exit", qApp, &QApplication::quit);

    trayIcon_->setContextMenu(trayMenu_);
    trayIcon_->show();

    connect(trayIcon_, &QSystemTrayIcon::activated,
            this, &MainWindow::onTrayActivated);
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick) {
        if (isVisible()) { hide(); }
        else { show(); raise(); activateWindow(); }
    }
}

void MainWindow::showThreatNotification(const QString& threatName, const QString& filePath)
{
    if (trayIcon_ && trayIcon_->isVisible()) {
        trayIcon_->showMessage(
            "Threat Detected",
            QString("%1\n%2").arg(threatName, filePath),
            QSystemTrayIcon::Warning,
            5000
        );
    }
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (trayIcon_ && trayIcon_->isVisible()) {
        hide();
        trayIcon_->showMessage(
            "CortexEDR",
            "Minimized to system tray. Double-click to restore.",
            QSystemTrayIcon::Information,
            2000
        );
        event->ignore();
    } else {
        event->accept();
    }
}

// ─── Stylesheet ───────────────────────────────────────────────────────────────

void MainWindow::applyStylesheet()
{
    // Try loading from file first; fall back to embedded minimal style
    QFile f(":/resources/stylesheet.qss");
    if (!f.open(QFile::ReadOnly)) {
        // Fallback: load relative to executable
        f.setFileName(QApplication::applicationDirPath() + "/resources/stylesheet.qss");
        (void)f.open(QFile::ReadOnly);
    }

    if (f.isOpen()) {
        setStyleSheet(QString::fromUtf8(f.readAll()));
        f.close();
    } else {
        // Minimal embedded fallback — glassmorphism
        setStyleSheet(R"(
            * { font-family: "Segoe UI Variable", "Segoe UI", sans-serif; }
            QMainWindow { background-color: #0c0e14; }
            QWidget { background-color: transparent; color: #e4e4e8; }
            QWidget#Sidebar { background-color: rgba(22,24,34,0.92); border-right: 1px solid rgba(255,255,255,0.04); }
            QListWidget#NavList { background-color: transparent; border: none; }
            QListWidget#NavList::item { color: rgba(255,255,255,0.45); padding-left: 14px; height: 36px; border-radius: 8px; }
            QListWidget#NavList::item:selected { background-color: rgba(255,255,255,0.10); color: #fff; }
            QListWidget#NavList::item:hover { background-color: rgba(255,255,255,0.06); color: rgba(255,255,255,0.75); }
            QPushButton#PrimaryBtn { background-color: rgba(34,197,94,0.85); color: #fff; border: none; border-radius: 8px; padding: 6px 18px; font-weight: 600; }
            QPushButton#DestructiveBtn { background-color: rgba(239,68,68,0.75); color: #fff; border: none; border-radius: 8px; padding: 6px 18px; font-weight: 600; }
            QPushButton { background-color: rgba(255,255,255,0.06); color: rgba(255,255,255,0.75); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 6px 18px; }
            QFrame#Card { background-color: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; }
            QProgressBar { background-color: rgba(255,255,255,0.06); border: none; border-radius: 4px; min-height: 6px; max-height: 6px; }
            QProgressBar::chunk { background-color: #4ade80; border-radius: 4px; }
            QStatusBar { background-color: rgba(16,18,26,0.95); border-top: 1px solid rgba(255,255,255,0.04); }
        )");
    }
}
