#ifndef HOSTSCANNERWINDOW_H
#define HOSTSCANNERWINDOW_H

#include <QMainWindow>
#include <QProcess>
#include <QThread>
#include <QSet>
#include <QMutex>

namespace Ui {
class HostScannerWindow;
}

class PingWorker : public QObject
{
    Q_OBJECT

public:
    explicit PingWorker(const QString &ip, QObject *parent = nullptr);
    void startPing();

signals:
    void pingFinished(const QString &ip, bool isAlive);

private slots:
    void processFinished(int exitCode, QProcess::ExitStatus exitStatus);

private:
    QString ipAddress;
    QProcess *pingProcess;
};

class ARPWorker : public QObject
{
    Q_OBJECT

public:
    explicit ARPWorker(QObject *parent = nullptr);

public slots:
    void startARPScan();

signals:
    void arpScanFinished(const QString &output);
};

class HostScannerWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit HostScannerWindow(QWidget *parent = nullptr);
    ~HostScannerWindow();

private slots:
    void on_startButton_clicked();
    void handlePingResult(const QString &ip, bool isAlive);
    void handleARPResult(const QString &output);
    void checkCompletion();
    void updateProgressBar();

private:
    Ui::HostScannerWindow *ui;
    int threadsNum = 20;
    QStringList ipList;
    QStringList aliveHosts;
    int currentIpIndex;
    int activePings;
    int totalPings;
    QSet<QString> pendingIps;
    QMutex mutex;

    void startPing();
    void startARP();
};

#endif // HOSTSCANNERWINDOW_H
