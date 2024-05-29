#include "hostscannerwindow.h"
#include "ui_hostscannerwindow.h"
#include <QDebug>
#include <QRegularExpression>

// PingWorker implementation
PingWorker::PingWorker(const QString &ip, QObject *parent)
    : QObject(parent), ipAddress(ip), pingProcess(nullptr)
{
}

void PingWorker::startPing()
{
    pingProcess = new QProcess(this); // 在 startPing 方法中创建 QProcess 对象
    connect(pingProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &PingWorker::processFinished);
#ifdef Q_OS_WIN
    pingProcess->start("ping", QStringList() << "-n" << "1" << "-w" << "100" << ipAddress); // -w 100 设置超时时间为100ms
#else
    pingProcess->start("ping", QStringList() << "-c" << "1" << "-W" << "1" << ipAddress); // -W 1 设置超时时间为1秒
#endif
}

void PingWorker::processFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    QString output = pingProcess->readAllStandardOutput();
    QString error = pingProcess->readAllStandardError();
    qDebug() << "Ping output for" << ipAddress << ":" << output;
    qDebug() << "Ping error for" << ipAddress << ":" << error;

    QRegularExpression regex("ttl=\\d+", QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatch match = regex.match(output);

    bool isAlive = (exitCode == 0 && match.hasMatch());
    emit pingFinished(ipAddress, isAlive);
    pingProcess->deleteLater(); // 清理 QProcess 对象
}

// HostScannerWindow implementation
HostScannerWindow::HostScannerWindow(QWidget *parent)
    : QMainWindow(parent),
    ui(new Ui::HostScannerWindow),
    currentIpIndex(0),
    activePings(0),
    totalPings(0)
{
    ui->setupUi(this);
    connect(ui->startButton, &QPushButton::clicked, this, &HostScannerWindow::on_startButton_clicked);
}

HostScannerWindow::~HostScannerWindow()
{
    delete ui;
}

void HostScannerWindow::on_startButton_clicked()
{
    QString network = ui->networkLineEdit->text();
    QString subnetMask = ui->subnetMaskLineEdit->text();

    // 清空之前的结果
    ui->resultTextEdit->clear();
    ipList.clear();
    aliveHosts.clear();
    currentIpIndex = 0;
    activePings = 0;
    totalPings = 0;
    pendingIps.clear();

    // 生成要ping的IP地址列表（简化处理，只处理C类子网）
    QStringList networkParts = network.split('.');
    if (networkParts.size() != 4) {
        ui->resultTextEdit->append("Invalid network format.");
        return;
    }

    for (int i = 1; i < 255; ++i) {
        ipList.append(QString("%1.%2.%3.%4").arg(networkParts[0]).arg(networkParts[1]).arg(networkParts[2]).arg(i));
    }

    // 开始ping IP地址
    if (!ipList.isEmpty()) {
        totalPings = ipList.size();
        for (int i = 0; i < 20 && i < ipList.size(); ++i) { // 同时启动20个ping
            startPing();
        }
    }
}

void HostScannerWindow::startPing()
{
    if (currentIpIndex < ipList.size()) {
        QString ip = ipList[currentIpIndex];
        currentIpIndex++;
        activePings++;
        pendingIps.insert(ip);

        PingWorker *worker = new PingWorker(ip);
        QThread *thread = new QThread;
        worker->moveToThread(thread);

        connect(thread, &QThread::started, worker, &PingWorker::startPing);
        connect(worker, &PingWorker::pingFinished, this, &HostScannerWindow::handlePingResult);
        connect(worker, &PingWorker::pingFinished, thread, &QThread::quit);
        connect(worker, &PingWorker::pingFinished, worker, &PingWorker::deleteLater);
        connect(thread, &QThread::finished, thread, &QThread::deleteLater);

        thread->start();
    }
}

void HostScannerWindow::handlePingResult(const QString &ip, bool isAlive)
{
    activePings--;
    pendingIps.remove(ip);

    if (isAlive) {
        ui->resultTextEdit->append(QString("%1 is alive").arg(ip));
        aliveHosts.append(ip);
    } else {
        ui->resultTextEdit->append(QString("%1 is not reachable").arg(ip));
    }

    if (currentIpIndex < ipList.size()) {
        startPing();
    }

    checkCompletion();
}

void HostScannerWindow::checkCompletion()
{
    if (activePings == 0 && pendingIps.isEmpty() && currentIpIndex == totalPings) {
        // 确保所有ping完成
        ui->resultTextEdit->append("Scan finished.");
        ui->resultTextEdit->append("Alive hosts:");
        for (const QString &host : aliveHosts) {
            ui->resultTextEdit->append(host);
        }
    }
}
