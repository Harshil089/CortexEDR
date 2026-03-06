#include "QuarantinePanel.hpp"
#include "EDRBridge.hpp"
#include <QHBoxLayout>
#include <QLabel>

QuarantinePanel::QuarantinePanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
}

void QuarantinePanel::setupUI()
{
    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(14);

    // ── Page header ──────────────────────────────────────────────────────────
    QHBoxLayout* headerRow = new QHBoxLayout();

    QLabel* pageTitle = new QLabel("Quarantine");
    pageTitle->setObjectName("PageTitle");
    QFont tf("Segoe UI", 20, QFont::DemiBold);
    pageTitle->setFont(tf);

    countLabel_ = new QLabel("0 items");
    countLabel_->setObjectName("PageSubtitle");
    countLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    headerRow->addWidget(pageTitle);
    headerRow->addStretch();
    headerRow->addWidget(countLabel_);
    root->addLayout(headerRow);

    QLabel* pageSub = new QLabel("Restore or permanently delete quarantined files");
    pageSub->setObjectName("PageSubtitle");
    root->addWidget(pageSub);
    root->addSpacing(4);

    // ── Table ────────────────────────────────────────────────────────────────
    table_ = new QTableWidget();
    table_->setColumnCount(5);
    table_->setHorizontalHeaderLabels({"File Name", "Threat Type", "Date", "Risk", "QuarantinePath"});
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    table_->setColumnHidden(4, true);  // quarantine path — used for actions, not displayed
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSortingEnabled(true);

    connect(table_, &QTableWidget::itemSelectionChanged, this, [this]() {
        bool sel = !table_->selectedItems().isEmpty();
        restoreBtn_->setEnabled(sel);
        deleteBtn_->setEnabled(sel);
    });

    root->addWidget(table_, 1);

    // ── Action buttons ───────────────────────────────────────────────────────
    QHBoxLayout* btnRow = new QHBoxLayout();
    btnRow->setSpacing(10);

    restoreBtn_ = new QPushButton("Restore Selected");
    restoreBtn_->setObjectName("PrimaryBtn");
    restoreBtn_->setFixedHeight(34);
    restoreBtn_->setCursor(Qt::PointingHandCursor);
    restoreBtn_->setEnabled(false);

    deleteBtn_ = new QPushButton("Delete Permanently");
    deleteBtn_->setObjectName("DestructiveBtn");
    deleteBtn_->setFixedHeight(34);
    deleteBtn_->setCursor(Qt::PointingHandCursor);
    deleteBtn_->setEnabled(false);

    refreshBtn_ = new QPushButton("Refresh");
    refreshBtn_->setObjectName("GhostBtn");
    refreshBtn_->setFixedHeight(34);
    refreshBtn_->setCursor(Qt::PointingHandCursor);

    connect(restoreBtn_, &QPushButton::clicked, this, &QuarantinePanel::onRestoreClicked);
    connect(deleteBtn_,  &QPushButton::clicked, this, &QuarantinePanel::onDeleteClicked);
    connect(refreshBtn_, &QPushButton::clicked, this, &QuarantinePanel::refreshTable);

    btnRow->addWidget(restoreBtn_);
    btnRow->addWidget(deleteBtn_);
    btnRow->addStretch();
    btnRow->addWidget(refreshBtn_);
    root->addLayout(btnRow);

    // Helper note
    QLabel* note = new QLabel("No action is performed until you confirm the dialog.");
    note->setStyleSheet("color: rgba(255,255,255,0.25); font-size: 11px;");
    root->addWidget(note);
}

// ─── Data ─────────────────────────────────────────────────────────────────────

void QuarantinePanel::refreshTable()
{
    table_->setSortingEnabled(false);
    auto entries = bridge_->getQuarantineEntries();

    table_->setRowCount(entries.size());
    countLabel_->setText(QString("%1 item(s)").arg(entries.size()));

    // Risk classification based on threat type keyword
    auto riskLevel = [](const QString& threatType) -> QString {
        QString t = threatType.toLower();
        if (t.contains("mimikatz") || t.contains("critical") || t.contains("ransomware"))
            return "CRITICAL";
        if (t.contains("keylogger") || t.contains("hacktool") || t.contains("high"))
            return "HIGH";
        if (t.contains("doubleext") || t.contains("suspicious") || t.contains("medium"))
            return "MEDIUM";
        return "LOW";
    };

    auto riskColor = [](const QString& risk) -> QString {
        if (risk == "CRITICAL") return "#f87171";
        if (risk == "HIGH")     return "#fbbf24";
        if (risk == "MEDIUM")   return "#60a5fa";
        return "rgba(255,255,255,0.35)";
    };

    for (int i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];

        auto* nameItem   = new QTableWidgetItem(e.fileName);
        auto* threatItem = new QTableWidgetItem(e.threatType);
        auto* dateItem   = new QTableWidgetItem(e.dateQuarantined.toString("yyyy-MM-dd hh:mm"));
        QString risk     = riskLevel(e.threatType);
        auto* riskItem   = new QTableWidgetItem(risk);
        auto* pathItem   = new QTableWidgetItem(e.quarantinePath);

        // Threat type — always red
        threatItem->setForeground(QColor("#f87171"));

        // Risk level — colored
        riskItem->setForeground(QColor(riskColor(risk)));
        QFont rf("Segoe UI", 11, QFont::Bold);
        riskItem->setFont(rf);
        riskItem->setTextAlignment(Qt::AlignCenter);

        // Timestamps — secondary color
        dateItem->setForeground(QColor(255,255,255,115));

        table_->setItem(i, 0, nameItem);
        table_->setItem(i, 1, threatItem);
        table_->setItem(i, 2, dateItem);
        table_->setItem(i, 3, riskItem);
        table_->setItem(i, 4, pathItem);
    }

    table_->setSortingEnabled(true);

    // Clear selection → disable buttons
    restoreBtn_->setEnabled(false);
    deleteBtn_->setEnabled(false);
}

// ─── Actions ──────────────────────────────────────────────────────────────────

void QuarantinePanel::onRestoreClicked()
{
    int row = table_->currentRow();
    if (row < 0) return;

    QString fileName      = table_->item(row, 0)->text();
    QString quarantinePath = table_->item(row, 4)->text();

    // Get original path from bridge entry
    auto entries = bridge_->getQuarantineEntries();
    QString originalPath;
    for (const auto& e : entries) {
        if (e.quarantinePath == quarantinePath) {
            originalPath = e.originalPath;
            break;
        }
    }

    auto reply = QMessageBox::warning(
        this,
        "Restore File",
        QString("Restore '%1' to its original location?\n\n"
                "This file was quarantined because it was flagged as a threat. "
                "Only restore if you are certain it is safe.")
            .arg(fileName),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if (reply == QMessageBox::Yes) {
        bridge_->restoreFile(quarantinePath, originalPath);
        refreshTable();
    }
}

void QuarantinePanel::onDeleteClicked()
{
    int row = table_->currentRow();
    if (row < 0) return;

    QString fileName       = table_->item(row, 0)->text();
    QString quarantinePath = table_->item(row, 4)->text();

    // Step 1 — warning
    auto step1 = QMessageBox::warning(
        this,
        "Delete Permanently",
        QString("Permanently delete '%1'?\n\nThis action cannot be undone.")
            .arg(fileName),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if (step1 != QMessageBox::Yes) return;

    // Step 2 — critical confirmation
    auto step2 = QMessageBox::critical(
        this,
        "Confirm Permanent Deletion",
        QString("Final confirmation: delete '%1' from disk permanently?")
            .arg(fileName),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if (step2 == QMessageBox::Yes) {
        bridge_->deleteFilePermanently(quarantinePath);
        refreshTable();
    }
}
