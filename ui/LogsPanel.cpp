#include "LogsPanel.hpp"
#include "EDRBridge.hpp"
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QLabel>

LogsPanel::LogsPanel(EDRBridge* bridge, QWidget* parent)
    : QWidget(parent), bridge_(bridge)
{
    setupUI();
}

void LogsPanel::setupUI()
{
    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(14);

    // ── Page header ──────────────────────────────────────────────────────────
    QLabel* pageTitle = new QLabel("Event Logs");
    pageTitle->setObjectName("PageTitle");
    QFont tf("Segoe UI", 20, QFont::DemiBold);
    pageTitle->setFont(tf);

    QLabel* pageSub = new QLabel("System events, threat detections, and scan activity");
    pageSub->setObjectName("PageSubtitle");

    root->addWidget(pageTitle);
    root->addWidget(pageSub);
    root->addSpacing(4);

    // ── Toolbar ───────────────────────────────────────────────────────────────
    QHBoxLayout* toolbar = new QHBoxLayout();
    toolbar->setSpacing(10);

    // Filter
    QLabel* filterLabel = new QLabel("Filter:");
    filterLabel->setStyleSheet("color: rgba(255,255,255,0.35); font-size: 12px;");

    filterCombo_ = new QComboBox();
    filterCombo_->addItems({"All", "Threats", "System Events", "Scan Logs"});
    filterCombo_->setFixedHeight(30);

    // Search
    searchEdit_ = new QLineEdit();
    searchEdit_->setPlaceholderText("Search file path or details...");
    searchEdit_->setFixedHeight(30);
    searchEdit_->setMinimumWidth(220);

    countLabel_ = new QLabel("0 entries");
    countLabel_->setStyleSheet("color: rgba(255,255,255,0.25); font-size: 12px;");

    refreshBtn_ = new QPushButton("Refresh");
    refreshBtn_->setObjectName("GhostBtn");
    refreshBtn_->setFixedHeight(30);
    refreshBtn_->setCursor(Qt::PointingHandCursor);

    exportBtn_ = new QPushButton("Export CSV");
    exportBtn_->setObjectName("GhostBtn");
    exportBtn_->setFixedHeight(30);
    exportBtn_->setCursor(Qt::PointingHandCursor);

    clearBtn_ = new QPushButton("Clear View");
    clearBtn_->setObjectName("GhostBtn");
    clearBtn_->setFixedHeight(30);
    clearBtn_->setCursor(Qt::PointingHandCursor);

    connect(filterCombo_, &QComboBox::currentTextChanged, this, &LogsPanel::onFilterChanged);
    connect(searchEdit_,  &QLineEdit::textChanged,        this, &LogsPanel::refreshLogs);
    connect(refreshBtn_,  &QPushButton::clicked,          this, &LogsPanel::refreshLogs);
    connect(exportBtn_,   &QPushButton::clicked,          this, &LogsPanel::onExportCsv);
    connect(clearBtn_,    &QPushButton::clicked,          this, [this]() {
        table_->setRowCount(0);
        countLabel_->setText("0 entries");
    });

    toolbar->addWidget(filterLabel);
    toolbar->addWidget(filterCombo_);
    toolbar->addWidget(searchEdit_, 1);
    toolbar->addStretch();
    toolbar->addWidget(countLabel_);
    toolbar->addWidget(refreshBtn_);
    toolbar->addWidget(exportBtn_);
    toolbar->addWidget(clearBtn_);
    root->addLayout(toolbar);

    // ── Log table ─────────────────────────────────────────────────────────────
    table_ = new QTableWidget();
    table_->setColumnCount(5);
    table_->setHorizontalHeaderLabels({"Timestamp", "Type", "Severity", "File Path", "Details"});
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSortingEnabled(true);

    root->addWidget(table_, 1);
}

// ─── Data ─────────────────────────────────────────────────────────────────────

void LogsPanel::refreshLogs()
{
    onFilterChanged(filterCombo_->currentText());
}

void LogsPanel::onFilterChanged(const QString& filter)
{
    auto entries = bridge_->getLogEntries(filter);
    const QString search = searchEdit_->text().trimmed();

    // Apply client-side search filter
    if (!search.isEmpty()) {
        QVector<LogEntry> filtered;
        filtered.reserve(entries.size());
        for (const auto& e : entries) {
            if (e.filePath.contains(search, Qt::CaseInsensitive) ||
                e.details.contains(search, Qt::CaseInsensitive)) {
                filtered.append(e);
            }
        }
        populateTable(filtered);
    } else {
        populateTable(entries);
    }
}

void LogsPanel::populateTable(const QVector<LogEntry>& entries)
{
    table_->setSortingEnabled(false);
    table_->setRowCount(entries.size());

    for (int i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];

        // Timestamp — monospace
        auto* tsItem = new QTableWidgetItem(
            e.timestamp.toString("yyyy-MM-dd hh:mm:ss.zzz"));
        tsItem->setFont(QFont("Cascadia Code", 10));
        tsItem->setForeground(QColor(255,255,255,90));

        // Type — color coded
        auto* typeItem = new QTableWidgetItem(e.eventType.toUpper());
        QFont typef("Segoe UI", 11, QFont::Bold);
        typeItem->setFont(typef);
        if (e.eventType == "Threat")
            typeItem->setForeground(QColor("#f87171"));
        else if (e.eventType == "Scan")
            typeItem->setForeground(QColor("#60a5fa"));
        else
            typeItem->setForeground(QColor(255,255,255,90));

        // Severity badge — color coded
        auto* sevItem = new QTableWidgetItem(e.severity.toUpper());
        QFont sevf("Segoe UI", 10, QFont::Bold);
        sevItem->setFont(sevf);
        sevItem->setTextAlignment(Qt::AlignCenter);
        if (e.severity == "Critical")
            sevItem->setForeground(QColor("#f87171"));
        else if (e.severity == "Warning")
            sevItem->setForeground(QColor("#fbbf24"));
        else
            sevItem->setForeground(QColor("#4ade80"));

        // File path — truncated in tooltip
        auto* pathItem = new QTableWidgetItem(e.filePath);
        pathItem->setForeground(QColor(255,255,255,115));
        pathItem->setFont(QFont("Cascadia Code", 10));

        // Details — truncated, full text in tooltip
        QString detailsShort = e.details.length() > 80
            ? e.details.left(77) + "..."
            : e.details;
        auto* detItem = new QTableWidgetItem(detailsShort);
        detItem->setToolTip(e.details);
        detItem->setForeground(QColor(255,255,255,180));

        table_->setItem(i, 0, tsItem);
        table_->setItem(i, 1, typeItem);
        table_->setItem(i, 2, sevItem);
        table_->setItem(i, 3, pathItem);
        table_->setItem(i, 4, detItem);
    }

    table_->setSortingEnabled(true);
    countLabel_->setText(QString("%1 entries").arg(entries.size()));
}

// ─── Export ───────────────────────────────────────────────────────────────────

void LogsPanel::onExportCsv()
{
    if (table_->rowCount() == 0) {
        QMessageBox::information(this, "Export", "No log entries to export.");
        return;
    }

    QString path = QFileDialog::getSaveFileName(
        this,
        "Export Logs",
        QString("cortexedr_logs_%1.csv")
            .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")),
        "CSV Files (*.csv)");

    if (path.isEmpty()) return;

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Export Failed",
                             "Could not open file for writing: " + path);
        return;
    }

    QTextStream out(&file);
    out << "Timestamp,Type,Severity,File Path,Details\n";

    for (int r = 0; r < table_->rowCount(); ++r) {
        QStringList row;
        for (int c = 0; c < 5; ++c) {
            QString cell = table_->item(r, c) ? table_->item(r, c)->text() : "";
            // Escape double-quotes and wrap fields in quotes
            cell.replace("\"", "\"\"");
            row << "\"" + cell + "\"";
        }
        out << row.join(",") << "\n";
    }

    file.close();
}
