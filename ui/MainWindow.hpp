#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <QListWidget>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>

class EDRBridge;
class DashboardPanel;
class QuickScanPanel;
class FullScanPanel;
class RealTimeProtectionPanel;
class SettingsPanel;
class QuarantinePanel;
class LogsPanel;
class AboutPanel;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(EDRBridge* bridge, QWidget* parent = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onNavigationChanged(int index);
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void showThreatNotification(const QString& threatName, const QString& filePath);
    void onBackendConnectionChanged(bool connected);
    void onThreatCountChanged(int count);

private:
    void setupUI();
    void setupSidebar();
    void setupContentArea();
    void setupStatusBar();
    void setupSystemTray();
    void applyStylesheet();

    EDRBridge* bridge_;

    // Layout
    QWidget*     centralWidget_;
    QHBoxLayout* mainLayout_;

    // Sidebar
    QWidget*     sidebarWidget_;
    QVBoxLayout* sidebarLayout_;
    QListWidget* navList_;
    QLabel*      logoLabel_;
    QLabel*      backendStatusLabel_;   // sidebar footer

    // Content
    QStackedWidget* contentStack_;

    // Panels (order matches contentStack_ index)
    DashboardPanel*          dashboardPanel_;   // 0
    QuickScanPanel*          quickScanPanel_;   // 1
    FullScanPanel*           fullScanPanel_;    // 2
    RealTimeProtectionPanel* rtpPanel_;         // 3
    QuarantinePanel*         quarantinePanel_;  // 4
    LogsPanel*               logsPanel_;        // 5
    SettingsPanel*           settingsPanel_;    // 6
    AboutPanel*              aboutPanel_;       // 7

    // Status bar labels
    QLabel* globalStatusLabel_;
    QLabel* threatCountStatusLabel_;
    QLabel* incidentStatusLabel_;
    QLabel* backendStatusBarLabel_;

    // System tray
    QSystemTrayIcon* trayIcon_;
    QMenu*           trayMenu_;
};
