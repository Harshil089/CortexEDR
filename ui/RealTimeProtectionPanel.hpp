#pragma once

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFrame>

class EDRBridge;

class RealTimeProtectionPanel : public QWidget {
    Q_OBJECT

public:
    explicit RealTimeProtectionPanel(EDRBridge* bridge, QWidget* parent = nullptr);

public slots:
    void refreshStatus();

private slots:
    void onToggleClicked();

private:
    void setupUI();
    void updateUI(bool active);
    QFrame* createMonitorRow(const QString& name, const QString& method,
                             QLabel*& dot, QLabel*& statusLabel);

    EDRBridge* bridge_;

    QPushButton* toggleBtn_;
    QLabel*      statusLabel_;
    QLabel*      statusDescLabel_;

    // Monitor dot + status label pairs
    QLabel* procDot_;
    QLabel* processMonitorStatus_;
    QLabel* regDot_;
    QLabel* registryMonitorStatus_;
    QLabel* fileDot_;
    QLabel* fileSystemStatus_;
    QLabel* netDot_;
    QLabel* networkMonitorStatus_;
};
