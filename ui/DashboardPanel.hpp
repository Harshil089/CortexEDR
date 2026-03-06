#pragma once

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFrame>
#include <QTimer>

class EDRBridge;

class DashboardPanel : public QWidget {
    Q_OBJECT

public:
    explicit DashboardPanel(EDRBridge* bridge, QWidget* parent = nullptr);

public slots:
    void refreshStatus();

signals:
    void quickScanRequested();

private:
    void setupUI();

    EDRBridge* bridge_;

    // Header
    QPushButton* quickScanBtn_;
    QLabel*      connectionIndicator_;
    QLabel*      connectionLabel_;

    // Status cards
    QFrame* protectionCard_;
    QFrame* lastScanCard_;
    QFrame* threatsCard_;
    QFrame* healthCard_;

    QLabel* protectionStatusLabel_;
    QLabel* lastScanLabel_;
    QLabel* threatsLabel_;
    QLabel* healthLabel_;
    QLabel* healthIndicator_;

    // Monitor row dots + status labels
    QLabel* procDot_;
    QLabel* procStatus_;
    QLabel* fileDot_;
    QLabel* fileStatus_;
    QLabel* netDot_;
    QLabel* netStatus_;
    QLabel* regDot_;
    QLabel* regStatus_;

    // Incident summary
    QFrame* incidentCard_;
    QLabel* activeIncidentsLabel_;
    QLabel* totalIncidentsLabel_;

    QTimer* refreshTimer_;
};
