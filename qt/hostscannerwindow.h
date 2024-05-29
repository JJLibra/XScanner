#ifndef HOSTSCANNERWINDOW_H
#define HOSTSCANNERWINDOW_H

#include <QMainWindow>
#include <QProcess>
#include <QThread>
#include <QSet>

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

class HostScannerWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit HostScannerWindow(QWidget *parent = nullptr);
    ~HostScannerWindow();

private slots:
    void on_startButton_clicked();
    void handlePingResult(const QString &ip, bool isAlive);
    void checkCompletion();

private:
    Ui::HostScannerWindow *ui;
    int threadsNum = 20;
    QStringList ipList;
    QStringList aliveHosts;
    int currentIpIndex;
    int activePings;
    int totalPings;
    QSet<QString> pendingIps;

    void startPing();
};

#endif // HOSTSCANNERWINDOW_H
