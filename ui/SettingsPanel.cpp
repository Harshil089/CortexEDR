#include "SettingsPanel.hpp"
#include "EDRBridge.hpp"
#include <QScrollArea>
#include <QHBoxLayout>

SettingsPanel::SettingsPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
}

void SettingsPanel::setupUI()
{
    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(14);

    // ── Page header ──────────────────────────────────────────────────────────
    QLabel* pageTitle = new QLabel("Settings");
    pageTitle->setObjectName("PageTitle");
    QFont tf("Segoe UI", 20, QFont::DemiBold);
    pageTitle->setFont(tf);

    QLabel* pageSub = new QLabel("Scan behavior, exclusions, and threat definitions");
    pageSub->setObjectName("PageSubtitle");

    root->addWidget(pageTitle);
    root->addWidget(pageSub);
    root->addSpacing(4);

    // ── Scrollable content ────────────────────────────────────────────────────
    QScrollArea* scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    QWidget* content = new QWidget();
    QVBoxLayout* contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(0, 0, 8, 0);
    contentLayout->setSpacing(14);

    // ── Section: Scan Sensitivity ─────────────────────────────────────────────
    {
        QFrame* sec = createSection("SCAN BEHAVIOR");
        QVBoxLayout* sl = qobject_cast<QVBoxLayout*>(sec->layout());

        // Slider row
        QHBoxLayout* sliderRow = new QHBoxLayout();
        QLabel* lowLabel = new QLabel("Low");
        lowLabel->setStyleSheet("color: rgba(255,255,255,0.30); font-size: 11px;");

        sensitivitySlider_ = new QSlider(Qt::Horizontal);
        sensitivitySlider_->setRange(0, 100);
        sensitivitySlider_->setValue(bridge_->scanSensitivity());

        QLabel* highLabel = new QLabel("High");
        highLabel->setStyleSheet("color: rgba(255,255,255,0.30); font-size: 11px;");

        sliderRow->addWidget(lowLabel);
        sliderRow->addWidget(sensitivitySlider_, 1);
        sliderRow->addWidget(highLabel);

        sensitivityLabel_ = new QLabel(
            QString("Detection Sensitivity: %1%").arg(bridge_->scanSensitivity()));
        sensitivityLabel_->setStyleSheet("color: #4ade80; font-size: 12px; font-weight: 600;");

        QLabel* sensDesc = new QLabel(
            "Higher sensitivity detects more threats but may increase false positives.");
        sensDesc->setStyleSheet("color: rgba(255,255,255,0.25); font-size: 11px;");
        sensDesc->setWordWrap(true);

        connect(sensitivitySlider_, &QSlider::valueChanged,
                this, &SettingsPanel::onSensitivityChanged);

        sl->addLayout(sliderRow);
        sl->addWidget(sensitivityLabel_);
        sl->addWidget(sensDesc);

        // Checkboxes
        QFrame* divider = new QFrame();
        divider->setObjectName("HRule");
        divider->setFrameShape(QFrame::HLine);
        divider->setFixedHeight(1);
        sl->addWidget(divider);

        heuristicCheck_ = new QCheckBox("Enable heuristic analysis (behavioral detection)");
        heuristicCheck_->setChecked(bridge_->heuristicScanEnabled());
        connect(heuristicCheck_, &QCheckBox::checkStateChanged,
                this, &SettingsPanel::onHeuristicChanged);

        autoScanCheck_ = new QCheckBox("Scan on system startup");
        autoScanCheck_->setChecked(bridge_->autoScanOnStartup());
        connect(autoScanCheck_, &QCheckBox::checkStateChanged,
                this, &SettingsPanel::onAutoScanChanged);

        sl->addWidget(heuristicCheck_);
        sl->addWidget(autoScanCheck_);

        contentLayout->addWidget(sec);
    }

    // ── Section: Exclusions ───────────────────────────────────────────────────
    {
        QFrame* sec = createSection("EXCLUSION FOLDERS");
        QVBoxLayout* sl = qobject_cast<QVBoxLayout*>(sec->layout());

        QLabel* desc = new QLabel(
            "Files in these folders are skipped during all scans.");
        desc->setStyleSheet("color: rgba(255,255,255,0.25); font-size: 11px;");
        desc->setWordWrap(true);
        sl->addWidget(desc);

        exclusionList_ = new QListWidget();
        exclusionList_->setMaximumHeight(150);
        for (const auto& folder : bridge_->exclusionFolders())
            exclusionList_->addItem(folder);
        sl->addWidget(exclusionList_);

        QHBoxLayout* exBtns = new QHBoxLayout();
        addExclusionBtn_ = new QPushButton("Add Folder");
        addExclusionBtn_->setObjectName("GhostBtn");
        addExclusionBtn_->setFixedHeight(30);
        addExclusionBtn_->setCursor(Qt::PointingHandCursor);

        removeExclusionBtn_ = new QPushButton("Remove Selected");
        removeExclusionBtn_->setObjectName("DestructiveBtn");
        removeExclusionBtn_->setFixedHeight(30);
        removeExclusionBtn_->setCursor(Qt::PointingHandCursor);
        removeExclusionBtn_->setEnabled(false);

        connect(addExclusionBtn_,    &QPushButton::clicked, this, &SettingsPanel::onAddExclusion);
        connect(removeExclusionBtn_, &QPushButton::clicked, this, &SettingsPanel::onRemoveExclusion);
        connect(exclusionList_, &QListWidget::itemSelectionChanged, this, [this]() {
            removeExclusionBtn_->setEnabled(!exclusionList_->selectedItems().isEmpty());
        });

        exBtns->addWidget(addExclusionBtn_);
        exBtns->addWidget(removeExclusionBtn_);
        exBtns->addStretch();
        sl->addLayout(exBtns);

        contentLayout->addWidget(sec);
    }

    // ── Section: Threat Definitions ───────────────────────────────────────────
    {
        QFrame* sec = createSection("THREAT DEFINITIONS");
        QVBoxLayout* sl = qobject_cast<QVBoxLayout*>(sec->layout());

        QHBoxLayout* defsRow = new QHBoxLayout();
        defsRow->setSpacing(14);

        updateDefsBtn_ = new QPushButton("Check for Updates");
        updateDefsBtn_->setObjectName("PrimaryBtn");
        updateDefsBtn_->setFixedHeight(34);
        updateDefsBtn_->setCursor(Qt::PointingHandCursor);

        defsStatusLabel_ = new QLabel("Definitions are up to date");
        defsStatusLabel_->setStyleSheet("color: #4ade80; font-size: 12px;");

        connect(updateDefsBtn_, &QPushButton::clicked,
                this, &SettingsPanel::onUpdateDefinitions);
        connect(bridge_, &EDRBridge::definitionsUpdated, this, [this](bool success) {
            updateDefsBtn_->setEnabled(true);
            updateDefsBtn_->setText("Check for Updates");
            if (success) {
                defsStatusLabel_->setText("Definitions are up to date");
                defsStatusLabel_->setStyleSheet("color: #4ade80; font-size: 12px;");
            } else {
                defsStatusLabel_->setText("Update failed — check connectivity");
                defsStatusLabel_->setStyleSheet("color: #f87171; font-size: 12px;");
            }
        });

        defsRow->addWidget(updateDefsBtn_);
        defsRow->addWidget(defsStatusLabel_);
        defsRow->addStretch();
        sl->addLayout(defsRow);

        contentLayout->addWidget(sec);
    }

    contentLayout->addStretch();
    scroll->setWidget(content);
    root->addWidget(scroll, 1);
}

QFrame* SettingsPanel::createSection(const QString& title)
{
    QFrame* sec = new QFrame();
    sec->setObjectName("Card");

    QVBoxLayout* l = new QVBoxLayout(sec);
    l->setContentsMargins(20, 16, 20, 16);
    l->setSpacing(12);

    QLabel* titleLabel = new QLabel(title);
    titleLabel->setObjectName("SectionTitle");
    l->addWidget(titleLabel);

    return sec;
}

// ─── Slots ────────────────────────────────────────────────────────────────────

void SettingsPanel::onSensitivityChanged(int value)
{
    sensitivityLabel_->setText(QString("Detection Sensitivity: %1%").arg(value));
    sensitivityLabel_->setStyleSheet(
        value >= 71 ? "color: #fbbf24; font-size: 12px; font-weight: 600;" :
        value <= 30 ? "color: #60a5fa; font-size: 12px; font-weight: 600;" :
                     "color: #4ade80; font-size: 12px; font-weight: 600;");
    bridge_->setScanSensitivity(value);
}

void SettingsPanel::onAutoScanChanged(Qt::CheckState state)
{
    bridge_->setAutoScanOnStartup(state == Qt::Checked);
}

void SettingsPanel::onHeuristicChanged(Qt::CheckState state)
{
    bridge_->setHeuristicScanEnabled(state == Qt::Checked);
}

void SettingsPanel::onAddExclusion()
{
    QString dir = QFileDialog::getExistingDirectory(this, "Select Exclusion Folder");
    if (dir.isEmpty()) return;

    for (int i = 0; i < exclusionList_->count(); ++i) {
        if (exclusionList_->item(i)->text() == dir)
            return;  // already present
    }
    exclusionList_->addItem(dir);
    bridge_->addExclusionFolder(dir);
}

void SettingsPanel::onRemoveExclusion()
{
    auto selected = exclusionList_->selectedItems();
    if (selected.isEmpty()) return;

    QString path = selected.first()->text();
    delete exclusionList_->takeItem(exclusionList_->row(selected.first()));
    bridge_->removeExclusionFolder(path);
}

void SettingsPanel::onUpdateDefinitions()
{
    updateDefsBtn_->setEnabled(false);
    updateDefsBtn_->setText("Checking...");
    defsStatusLabel_->setText("Downloading latest definitions...");
    defsStatusLabel_->setStyleSheet("color: #fbbf24; font-size: 12px;");
    bridge_->updateDefinitions();
}
