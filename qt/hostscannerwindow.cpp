#include "hostscannerwindow.h"
#include "ui_hostscannerwindow.h"
#include <QDebug>
#include <QRegularExpression>
#include <QMutexLocker>

PingWorker::PingWorker(const QString &ip, QObject *parent)
    : QObject(parent), ipAddress(ip), pingProcess(nullptr)
{
}

void PingWorker::startPing()
{
    pingProcess = new QProcess(this);
    connect(pingProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &PingWorker::processFinished);

#ifdef Q_OS_WIN
    pingProcess->start("ping", QStringList() << "-n" << "1" << "-w" << "1000" << ipAddress); // -w 1000 设置超时时间为1s
#else
    pingProcess->start("ping", QStringList() << "-c" << "1" << "-W" << "1" << ipAddress); // -W 1 设置超时时间为1秒
#endif
}

void PingWorker::processFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    QString output = pingProcess->readAllStandardOutput();
    QString error = pingProcess->readAllStandardError();

    QRegularExpression regex("ttl=\\d+", QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatch match = regex.match(output);

    bool isAlive = (exitCode == 0 && match.hasMatch());
    emit pingFinished(ipAddress, isAlive);
    pingProcess->deleteLater();
}

HostScannerWindow::HostScannerWindow(QWidget *parent)
    : QMainWindow(parent),
    ui(new Ui::HostScannerWindow),
    currentIpIndex(0),
    activePings(0),
    totalPings(0)
{
    ui->setupUi(this);
    connect(ui->startButton, &QPushButton::clicked, this, &HostScannerWindow::on_startButton_clicked);
    ui->progressBar->setValue(0);
    ui->progressBar->setRange(0, 100);  // 进度条的范围从0到100
}

HostScannerWindow::~HostScannerWindow()
{
    delete ui;
}

void HostScannerWindow::on_startButton_clicked()
{
    QString network = ui->networkLineEdit->text();
    QString subnetMask = ui->subnetMaskLineEdit->text();
    QString scanMethod = ui->scanMethodComboBox->currentText();

    if (network.isEmpty()) {
        ui->resultTextEdit->append("请输入需要检查的网段！");
        return;
    }
    if (subnetMask.isEmpty()) {
        ui->resultTextEdit->append("请输入子网掩码！");
        return;
    }

    // 初始化
    ui->resultTextEdit->clear();
    ui->aliveHostsTextEdit->clear();
    ui->progressBar->setValue(0);  // 重置进度条
    ipList.clear();
    aliveHosts.clear();
    pendingIps.clear();
    currentIpIndex = 0;
    activePings = 0;
    totalPings = 0;

    QStringList networkParts = network.split('.'); // ping IP 列表：C类子网
    if (networkParts.size() != 4) {
        ui->resultTextEdit->append("无效网段");
        return;
    }

    for (int i = 1; i < 255; ++i) { // 生成 IP 列表（254）
        ipList.append(QString("%1.%2.%3.%4").arg(networkParts[0]).arg(networkParts[1]).arg(networkParts[2]).arg(i));
    }

    if (!ipList.isEmpty()) {
        totalPings = ipList.size();

        if (scanMethod == "Ping") {
            for (int i = 0; i < threadsNum && i < ipList.size(); ++i) { // 多线程（20）：根据索引值 currentIpIndex 轮流取
                startPing(); // 开 ping
            }
        } else if (scanMethod == "ARP") {
            startARPScan(); // 开 ARP 扫描
        }
    }
}

void HostScannerWindow::startPing()
{
    if (currentIpIndex < ipList.size()) {
        QString ip = ipList[currentIpIndex];
        {
            QMutexLocker locker(&mutex);
            currentIpIndex++;
            activePings++;
            pendingIps.insert(ip);
        }

        PingWorker *worker = new PingWorker(ip); // 具体操作见 PingWorker 类
        QThread *thread = new QThread;
        worker->moveToThread(thread);

        // 线程管理
        connect(thread, &QThread::started, worker, &PingWorker::startPing);
        connect(worker, &PingWorker::pingFinished, this, &HostScannerWindow::handlePingResult);
        connect(worker, &PingWorker::pingFinished, thread, &QThread::quit);
        connect(worker, &PingWorker::pingFinished, worker, &PingWorker::deleteLater);
        connect(thread, &QThread::finished, thread, &QThread::deleteLater);

        thread->start();
    }
}

void HostScannerWindow::startARPScan()
{
    for (int i = 0; i < threadsNum && i < ipList.size(); ++i) {
        startPingForARP(); // 开始多线程ping，目的是填充ARP缓存
    }
}

void HostScannerWindow::startPingForARP()
{
    if (currentIpIndex < ipList.size()) {
        QString ip = ipList[currentIpIndex];
        {
            QMutexLocker locker(&mutex);
            currentIpIndex++;
            activePings++;
            pendingIps.insert(ip);
        }

        QThread *thread = new QThread;
        PingWorker *worker = new PingWorker(ip);
        worker->moveToThread(thread);

        connect(thread, &QThread::started, worker, &PingWorker::startPing);
        connect(worker, &PingWorker::pingFinished, this, [this](const QString &ip, bool isAlive) {
            QMutexLocker locker(&mutex);
            activePings--;
            pendingIps.remove(ip);

            if (currentIpIndex < ipList.size()) {
                startPingForARP();
            }

            if (activePings == 0) {
                // All pings are done, now read the ARP cache
                handleARPScan();
            }
        });

        connect(worker, &PingWorker::pingFinished, thread, &QThread::quit);
        connect(worker, &PingWorker::pingFinished, worker, &PingWorker::deleteLater);
        connect(thread, &QThread::finished, thread, &QThread::deleteLater);

        thread->start();
    }
}

void HostScannerWindow::handleARPScan()
{
    QProcess *arpProcess = new QProcess(this);
    connect(arpProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &HostScannerWindow::handleARPScanFinished);
    arpProcess->start("arp", QStringList() << "-a");
}

void HostScannerWindow::handleARPScanFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    QProcess *arpProcess = qobject_cast<QProcess*>(sender());
    QString output = arpProcess->readAllStandardOutput();
    QStringList lines = output.split('\n');
    
    foreach (const QString &line, lines) {
        QRegularExpression regex("([0-9]{1,3}\\.){3}[0-9]{1,3}");
        QRegularExpressionMatch match = regex.match(line);
        if (match.hasMatch()) {
            QString ip = match.captured(0);
            ui->resultTextEdit->append(QString("%1 is alive").arg(ip));
            aliveHosts.append(ip);
        }
    }

    updateProgressBar();  // 更新进度条
    checkCompletion();
}

void HostScannerWindow::handlePingResult(const QString &ip, bool isAlive)
{
    {
        QMutexLocker locker(&mutex);
        activePings--;
        pendingIps.remove(ip);
    }

    if (isAlive) {
        ui->resultTextEdit->append(QString("%1 is alive").arg(ip));
        aliveHosts.append(ip);
    } else {
        ui->resultTextEdit->append(QString("%1 is not reachable").arg(ip));
    }

    updateProgressBar();  // 更新进度条

    if (currentIpIndex < ipList.size()) {
        startPing();
    }

    checkCompletion();
}

void HostScannerWindow::updateProgressBar()
{
    int scanned = totalPings - ipList.size() + currentIpIndex;
    int progress = (scanned * 100) / totalPings;
    ui->progressBar->setValue(progress);
}

void HostScannerWindow::checkCompletion()
{
    QMutexLocker locker(&mutex);

    if (activePings < 0) activePings++;
    if (activePings == 0 && pendingIps.isEmpty() && currentIpIndex == totalPings) {
        ui->resultTextEdit->append("网段扫描已完成");
        ui->aliveHostsTextEdit->append("以下主机已开启");
        for (const QString &host : aliveHosts) {
            ui->aliveHostsTextEdit->append(host);
        }
    }
}
