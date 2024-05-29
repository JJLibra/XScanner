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
    QStringList ipList;
    QStringList aliveHosts;
    int currentIpIndex;
    int activePings;
    int totalPings; // 用于跟踪总的 ping 次数
    QSet<QString> pendingIps; // 用于跟踪仍在进行中的ping请求

    void startPing();
};

#endif // HOSTSCANNERWINDOW_H
