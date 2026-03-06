#pragma once

#include <QFileDialog>
#include <QFrame>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWidget>


class EDRBridge;

class QuickScanPanel : public QWidget {
  Q_OBJECT

public:
  explicit QuickScanPanel(EDRBridge *bridge, QWidget *parent = nullptr);

public slots:
  void startScan();
  void onProgressChanged(int percent);
  void onCurrentFileChanged(const QString &filePath);
  void onThreatDetected(const QString &filePath, const QString &threatName);
  void onScanFinished(int totalFiles, int threatsFound);

private:
  void setupUI();
  void setIdleState();
  void setScanningState();

  EDRBridge *bridge_;

  QLabel *titleLabel_;
  QLabel *statusLabel_;
  QLabel *currentFileLabel_;
  QLabel *threatsCountLabel_;
  QProgressBar *progressBar_;
  QPushButton *startBtn_;
  QPushButton *cancelBtn_;
  QTextEdit *resultsLog_;
  QFrame *summaryFrame_;
  QLabel *summaryLabel_;
  QLabel *selectedPathLabel_;
  QLabel *errorLabel_;

  int threatsFound_{0};
};
