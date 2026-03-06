#pragma once

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QComboBox>
#include <QHeaderView>
#include <QLineEdit>

struct LogEntry;
class EDRBridge;

class LogsPanel : public QWidget {
    Q_OBJECT

public:
    explicit LogsPanel(EDRBridge* bridge, QWidget* parent = nullptr);

public slots:
    void refreshLogs();

private slots:
    void onFilterChanged(const QString& filter);
    void onExportCsv();

private:
    void setupUI();
    void populateTable(const QVector<LogEntry>& entries);

    EDRBridge* bridge_;

    QComboBox*    filterCombo_;
    QLineEdit*    searchEdit_;
    QTableWidget* table_;
    QPushButton*  refreshBtn_;
    QPushButton*  exportBtn_;
    QPushButton*  clearBtn_;
    QLabel*       countLabel_;
};
