#include "FullScanPanel.hpp"
#include "EDRBridge.hpp"

FullScanPanel::FullScanPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
    setIdleState();
}

void FullScanPanel::setupUI()
{
    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(14);

    // ── Page header ──────────────────────────────────────────────────────────
    QLabel* pageTitle = new QLabel("Full System Scan");
    pageTitle->setObjectName("PageTitle");
    QFont tf("Segoe UI", 20, QFont::DemiBold);
    pageTitle->setFont(tf);

    QLabel* pageSub = new QLabel("Deep scan of all files on all drives");
    pageSub->setObjectName("PageSubtitle");

    root->addWidget(pageTitle);
    root->addWidget(pageSub);
    root->addSpacing(4);

    // ── Status card ──────────────────────────────────────────────────────────
    QFrame* statusCard = new QFrame();
    statusCard->setObjectName("Card");
    {
        QVBoxLayout* sl = new QVBoxLayout(statusCard);
        sl->setContentsMargins(20, 16, 20, 16);
        sl->setSpacing(10);

        statusLabel_ = new QLabel("Ready");
        QFont sf("Segoe UI", 14, QFont::DemiBold);
        statusLabel_->setFont(sf);
        statusLabel_->setStyleSheet("color: rgba(255,255,255,0.35);");

        progressBar_ = new QProgressBar();
        progressBar_->setObjectName("ScanningBar");
        progressBar_->setRange(0, 100);
        progressBar_->setValue(0);
        progressBar_->setTextVisible(false);

        // Current file + ETA on same row
        QHBoxLayout* infoRow = new QHBoxLayout();
        currentFileLabel_ = new QLabel();
        currentFileLabel_->setStyleSheet(
            "color: rgba(255,255,255,0.25); font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 11px;");

        estimatedTimeLabel_ = new QLabel();
        estimatedTimeLabel_->setStyleSheet(
            "color: rgba(255,255,255,0.35); font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 11px;");
        estimatedTimeLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

        infoRow->addWidget(currentFileLabel_, 1);
        infoRow->addWidget(estimatedTimeLabel_);

        threatsCountLabel_ = new QLabel("Threats found: 0");
        QFont tf2("Segoe UI", 12, QFont::DemiBold);
        threatsCountLabel_->setFont(tf2);
        threatsCountLabel_->setStyleSheet("color: #4ade80;");

        sl->addWidget(statusLabel_);
        sl->addWidget(progressBar_);
        sl->addLayout(infoRow);
        sl->addWidget(threatsCountLabel_);
    }
    root->addWidget(statusCard);

    // ── Action buttons ───────────────────────────────────────────────────────
    QHBoxLayout* btnRow = new QHBoxLayout();
    btnRow->setSpacing(10);

    startBtn_ = new QPushButton("Start Full Scan");
    startBtn_->setObjectName("PrimaryBtn");
    startBtn_->setFixedHeight(34);
    startBtn_->setCursor(Qt::PointingHandCursor);

    pauseBtn_ = new QPushButton("Pause");
    pauseBtn_->setObjectName("WarningBtn");
    pauseBtn_->setFixedHeight(34);
    pauseBtn_->setCursor(Qt::PointingHandCursor);
    pauseBtn_->setVisible(false);

    resumeBtn_ = new QPushButton("Resume");
    resumeBtn_->setObjectName("PrimaryBtn");
    resumeBtn_->setFixedHeight(34);
    resumeBtn_->setCursor(Qt::PointingHandCursor);
    resumeBtn_->setVisible(false);

    cancelBtn_ = new QPushButton("Cancel");
    cancelBtn_->setObjectName("DestructiveBtn");
    cancelBtn_->setFixedHeight(34);
    cancelBtn_->setCursor(Qt::PointingHandCursor);
    cancelBtn_->setVisible(false);

    connect(startBtn_, &QPushButton::clicked, this, &FullScanPanel::startScan);
    connect(pauseBtn_, &QPushButton::clicked, this, [this]() {
        bridge_->pauseScan();
        isPaused_ = true;
        pauseBtn_->setVisible(false);
        resumeBtn_->setVisible(true);
        statusLabel_->setText("Paused");
        statusLabel_->setStyleSheet("color: #fbbf24; font-size: 14px; font-weight: 600;");
    });
    connect(resumeBtn_, &QPushButton::clicked, this, [this]() {
        bridge_->resumeScan();
        isPaused_ = false;
        resumeBtn_->setVisible(false);
        pauseBtn_->setVisible(true);
        statusLabel_->setText("Scanning...");
        statusLabel_->setStyleSheet("color: #60a5fa; font-size: 14px; font-weight: 600;");
    });
    connect(cancelBtn_, &QPushButton::clicked, bridge_, &EDRBridge::cancelScan);

    btnRow->addWidget(startBtn_);
    btnRow->addWidget(pauseBtn_);
    btnRow->addWidget(resumeBtn_);
    btnRow->addWidget(cancelBtn_);
    btnRow->addStretch();
    root->addLayout(btnRow);

    // ── Directory traversal log ───────────────────────────────────────────────
    QLabel* logTitle = new QLabel("SCAN LOG");
    logTitle->setObjectName("SectionTitle");
    root->addSpacing(4);
    root->addWidget(logTitle);

    directoryLog_ = new QTextEdit();
    directoryLog_->setReadOnly(true);
    directoryLog_->setPlaceholderText("Real-time scan activity will appear here...");
    directoryLog_->setMinimumHeight(200);
    root->addWidget(directoryLog_, 1);
}

// ─── State Machine ────────────────────────────────────────────────────────────

void FullScanPanel::startScan()
{
    setScanningState();
    threatsFound_ = 0;
    directoryLog_->clear();
    bridge_->startFullScan();
}

void FullScanPanel::setIdleState()
{
    statusLabel_->setText("Ready");
    statusLabel_->setStyleSheet("color: rgba(255,255,255,0.35); font-size: 14px; font-weight: 600;");
    progressBar_->setValue(0);
    currentFileLabel_->clear();
    estimatedTimeLabel_->clear();
    threatsCountLabel_->setText("Threats found: 0");
    threatsCountLabel_->setStyleSheet("color: #4ade80; font-size: 12px; font-weight: 600;");
    startBtn_->setVisible(true);
    startBtn_->setEnabled(true);
    pauseBtn_->setVisible(false);
    resumeBtn_->setVisible(false);
    cancelBtn_->setVisible(false);
    isPaused_ = false;
}

void FullScanPanel::setScanningState()
{
    statusLabel_->setText("Scanning...");
    statusLabel_->setStyleSheet("color: #60a5fa; font-size: 14px; font-weight: 600;");
    startBtn_->setVisible(false);
    pauseBtn_->setVisible(true);
    cancelBtn_->setVisible(true);
}

// ─── Signal Handlers ──────────────────────────────────────────────────────────

void FullScanPanel::onProgressChanged(int percent)
{
    progressBar_->setValue(percent);
}

void FullScanPanel::onCurrentFileChanged(const QString& filePath)
{
    QString display = filePath.length() > 90
        ? "..." + filePath.right(87)
        : filePath;
    currentFileLabel_->setText(display);

    // Log every 5th file to avoid flooding
    static int logCount = 0;
    if (++logCount % 5 == 0) {
        directoryLog_->append(
            QString("<span style='color:rgba(255,255,255,0.12);'>%1</span> "
                    "<span style='color:rgba(255,255,255,0.30);'>%2</span>")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"),
                     filePath.toHtmlEscaped()));
        QTextCursor c = directoryLog_->textCursor();
        c.movePosition(QTextCursor::End);
        directoryLog_->setTextCursor(c);
    }
}

void FullScanPanel::onThreatDetected(const QString& filePath, const QString& threatName)
{
    threatsFound_++;
    threatsCountLabel_->setText(QString("Threats found: %1").arg(threatsFound_));
    threatsCountLabel_->setStyleSheet("color: #f87171; font-size: 12px; font-weight: 600;");

    directoryLog_->append(
        QString("<span style='color:#f87171;font-weight:600;'>THREAT</span> "
                "<span style='color:#fbbf24;'>%1</span> "
                "<span style='color:rgba(255,255,255,0.35);'>&nbsp;in %2</span>")
            .arg(threatName.toHtmlEscaped(), filePath.toHtmlEscaped()));
}

void FullScanPanel::onScanFinished(int totalFiles, int threatsFound)
{
    progressBar_->setValue(100);
    estimatedTimeLabel_->setText("Complete");
    currentFileLabel_->setText("Scan finished");

    const QString color = threatsFound > 0 ? "#f87171" : "#4ade80";
    if (threatsFound > 0) {
        statusLabel_->setText(QString("Complete — %1 threat(s) found").arg(threatsFound));
        statusLabel_->setStyleSheet("color: #f87171; font-size: 14px; font-weight: 600;");
    } else {
        statusLabel_->setText("Complete — No threats found");
        statusLabel_->setStyleSheet("color: #4ade80; font-size: 14px; font-weight: 600;");
    }

    directoryLog_->append(
        QString("<br><span style='color:rgba(255,255,255,0.10);'>─────────────────────────────</span><br>"
                "<span style='color:rgba(255,255,255,0.85);'>Files scanned: %1</span>   "
                "<span style='color:%2;'>Threats: %3</span>")
            .arg(totalFiles).arg(color).arg(threatsFound));

    startBtn_->setVisible(true);
    startBtn_->setEnabled(true);
    pauseBtn_->setVisible(false);
    resumeBtn_->setVisible(false);
    cancelBtn_->setVisible(false);
}

void FullScanPanel::onEstimatedTimeChanged(const QString& timeRemaining)
{
    estimatedTimeLabel_->setText("ETA " + timeRemaining);
}
