#include "QuickScanPanel.hpp"
#include "EDRBridge.hpp"

QuickScanPanel::QuickScanPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
    setIdleState();
}

void QuickScanPanel::setupUI()
{
    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(14);

    // ── Page header ──────────────────────────────────────────────────────────
    QLabel* pageTitle = new QLabel("Quick Scan");
    pageTitle->setObjectName("PageTitle");
    QFont tf("Segoe UI", 20, QFont::DemiBold);
    pageTitle->setFont(tf);

    QLabel* pageSub = new QLabel("Select a folder to scan for threats");
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

        currentFileLabel_ = new QLabel();
        currentFileLabel_->setStyleSheet(
            "color: rgba(255,255,255,0.25); font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 11px;");
        currentFileLabel_->setWordWrap(false);

        threatsCountLabel_ = new QLabel("Threats found: 0");
        QFont tf2("Segoe UI", 12, QFont::DemiBold);
        threatsCountLabel_->setFont(tf2);
        threatsCountLabel_->setStyleSheet("color: #4ade80;");

        sl->addWidget(statusLabel_);
        sl->addWidget(progressBar_);
        sl->addWidget(currentFileLabel_);
        sl->addWidget(threatsCountLabel_);
    }
    root->addWidget(statusCard);

    // ── Selected path display ────────────────────────────────────────────────
    selectedPathLabel_ = new QLabel();
    selectedPathLabel_->setStyleSheet(
        "color: rgba(255,255,255,0.25); font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 11px;");
    selectedPathLabel_->setWordWrap(true);
    root->addWidget(selectedPathLabel_);

    // ── Inline error label ───────────────────────────────────────────────────
    errorLabel_ = new QLabel();
    errorLabel_->setStyleSheet("color: #f87171; font-size: 12px;");
    errorLabel_->setVisible(false);
    root->addWidget(errorLabel_);

    // ── Action buttons ───────────────────────────────────────────────────────
    QHBoxLayout* btnRow = new QHBoxLayout();
    btnRow->setSpacing(10);

    startBtn_ = new QPushButton("Select Folder and Scan");
    startBtn_->setObjectName("PrimaryBtn");
    startBtn_->setFixedHeight(34);
    startBtn_->setCursor(Qt::PointingHandCursor);

    cancelBtn_ = new QPushButton("Cancel");
    cancelBtn_->setObjectName("DestructiveBtn");
    cancelBtn_->setFixedHeight(34);
    cancelBtn_->setCursor(Qt::PointingHandCursor);
    cancelBtn_->setVisible(false);

    connect(startBtn_,  &QPushButton::clicked, this,    &QuickScanPanel::startScan);
    connect(cancelBtn_, &QPushButton::clicked, bridge_, &EDRBridge::cancelScan);

    btnRow->addWidget(startBtn_);
    btnRow->addWidget(cancelBtn_);
    btnRow->addStretch();
    root->addLayout(btnRow);

    // ── Detections log ───────────────────────────────────────────────────────
    QLabel* detTitle = new QLabel("DETECTIONS");
    detTitle->setObjectName("SectionTitle");
    root->addSpacing(4);
    root->addWidget(detTitle);

    resultsLog_ = new QTextEdit();
    resultsLog_->setReadOnly(true);
    resultsLog_->setPlaceholderText("No threats detected.");
    resultsLog_->setMinimumHeight(120);
    root->addWidget(resultsLog_, 1);

    // ── Summary banner (hidden until scan complete) ───────────────────────────
    summaryFrame_ = new QFrame();
    summaryFrame_->setObjectName("Card");
    summaryFrame_->setVisible(false);
    {
        QHBoxLayout* sl = new QHBoxLayout(summaryFrame_);
        sl->setContentsMargins(20, 12, 20, 12);
        summaryLabel_ = new QLabel();
        QFont sf("Segoe UI", 13, QFont::DemiBold);
        summaryLabel_->setFont(sf);
        sl->addWidget(summaryLabel_);
    }
    root->addWidget(summaryFrame_);
}

// ─── State Machine ────────────────────────────────────────────────────────────

void QuickScanPanel::startScan()
{
    errorLabel_->setVisible(false);

    QString folder = QFileDialog::getExistingDirectory(
        this, "Select Folder to Scan", QString(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);

    if (folder.isEmpty())
        return;

    setScanningState();
    threatsFound_ = 0;
    resultsLog_->clear();
    summaryFrame_->setVisible(false);
    selectedPathLabel_->setText("Scanning: " + folder);
    bridge_->startCustomScan({folder});
}

void QuickScanPanel::setIdleState()
{
    statusLabel_->setText("Ready");
    statusLabel_->setStyleSheet("color: rgba(255,255,255,0.35); font-size: 14px; font-weight: 600;");
    progressBar_->setValue(0);
    currentFileLabel_->clear();
    threatsCountLabel_->setText("Threats found: 0");
    threatsCountLabel_->setStyleSheet("color: #4ade80; font-size: 12px; font-weight: 600;");
    startBtn_->setVisible(true);
    startBtn_->setEnabled(true);
    cancelBtn_->setVisible(false);
}

void QuickScanPanel::setScanningState()
{
    statusLabel_->setText("Scanning...");
    statusLabel_->setStyleSheet("color: #60a5fa; font-size: 14px; font-weight: 600;");
    startBtn_->setVisible(false);
    cancelBtn_->setVisible(true);
}

// ─── Signal Handlers ──────────────────────────────────────────────────────────

void QuickScanPanel::onProgressChanged(int percent)
{
    progressBar_->setValue(percent);
}

void QuickScanPanel::onCurrentFileChanged(const QString& filePath)
{
    QString display = filePath.length() > 90
        ? "..." + filePath.right(87)
        : filePath;
    currentFileLabel_->setText(display);
}

void QuickScanPanel::onThreatDetected(const QString& filePath, const QString& threatName)
{
    threatsFound_++;
    threatsCountLabel_->setText(QString("Threats found: %1").arg(threatsFound_));
    threatsCountLabel_->setStyleSheet("color: #f87171; font-size: 12px; font-weight: 600;");

    resultsLog_->append(
        QString("<span style='color:#f87171;font-weight:600;'>THREAT</span> "
                "<span style='color:rgba(255,255,255,0.85);'>%1</span> "
                "<span style='color:rgba(255,255,255,0.35);'>&nbsp;in %2</span>")
            .arg(threatName.toHtmlEscaped(), filePath.toHtmlEscaped()));
}

void QuickScanPanel::onScanFinished(int totalFiles, int threatsFound)
{
    progressBar_->setValue(100);
    currentFileLabel_->setText("Scan complete");

    if (threatsFound > 0) {
        statusLabel_->setText("Threats detected");
        statusLabel_->setStyleSheet("color: #f87171; font-size: 14px; font-weight: 600;");
        summaryFrame_->setStyleSheet(
            "QFrame { background-color: rgba(239,68,68,0.06); "
            "border: 1px solid rgba(239,68,68,0.15); border-radius: 12px; }");
        summaryLabel_->setText(
            QString("%1 files scanned  —  %2 threat(s) detected")
                .arg(totalFiles).arg(threatsFound));
        summaryLabel_->setStyleSheet("color: #f87171;");
    } else {
        statusLabel_->setText("No threats found");
        statusLabel_->setStyleSheet("color: #4ade80; font-size: 14px; font-weight: 600;");
        summaryFrame_->setStyleSheet(
            "QFrame { background-color: rgba(34,197,94,0.06); "
            "border: 1px solid rgba(34,197,94,0.15); border-radius: 12px; }");
        summaryLabel_->setText(
            QString("%1 files scanned  —  No threats detected").arg(totalFiles));
        summaryLabel_->setStyleSheet("color: #4ade80;");
    }

    summaryFrame_->setVisible(true);
    startBtn_->setVisible(true);
    startBtn_->setEnabled(true);
    cancelBtn_->setVisible(false);
}
