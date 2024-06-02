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

ARPWorker::ARPWorker(QObject *parent) : QObject(parent)
{
}

void ARPWorker::startARPScan()
{
    QProcess *arpProcess = new QProcess(this);
    connect(arpProcess, &QProcess::finished, this, [this, arpProcess](int exitCode, QProcess::ExitStatus exitStatus) {
        QString output = arpProcess->readAllStandardOutput();
        qDebug() << "ARP output:" << output; // 添加调试信息，查看ARP命令输出
        emit arpScanFinished(output);
        arpProcess->deleteLater();
    });
    arpProcess->start("arp -a");
}

HostScannerWindow::HostScannerWindow(QWidget *parent)
    : QMainWindow(parent),
    ui(new Ui::HostScannerWindow),
    currentIpIndex(0),
    activePings(0),
    totalPings(0)
{
    ui->setupUi(this);
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
            qDebug() << "ARP";
            ui->resultTextEdit->append("ARP正在开发中...");
            startARP(); // 开 ARP
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

void HostScannerWindow::startARP()
{
    ARPWorker *worker = new ARPWorker();
    QThread *thread = new QThread;
    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &ARPWorker::startARPScan);
    connect(worker, &ARPWorker::arpScanFinished, this, &HostScannerWindow::handleARPResult);
    connect(worker, &ARPWorker::arpScanFinished, thread, &QThread::quit);
    connect(worker, &ARPWorker::arpScanFinished, worker, &ARPWorker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    thread->start();
}

void HostScannerWindow::handleARPResult(const QString &output)
{
    qDebug() << "处理ARP表数据";
    qDebug() << "arp -a output:" << output; // 打印ARP命令输出

    QRegularExpression regex(R"((\d+\.\d+\.\d+\.\d+)\s+((?:[a-fA-F0-9]{2}-){5}[a-fA-F0-9]{2})\s+(\S+))");
    QRegularExpressionMatchIterator i = regex.globalMatch(output);

    while (i.hasNext()) {
        QRegularExpressionMatch match = i.next();
        QString ip = match.captured(1);
        QString mac = match.captured(2);
        QString type = match.captured(3);

        // 只处理类型为“动态”的条目
        if (type == "动态") {
            qDebug() << "IP Address:" << ip << "MAC Address:" << mac;
            ui->resultTextEdit->append(QString("IP Address: %1, MAC Address: %2").arg(ip).arg(mac));
            aliveHosts.append(ip);
        }
    }

    ui->progressBar->setValue(100);  // ARP扫描一次性完成，直接更新进度条
    ui->resultTextEdit->append("ARP扫描已完成");

    ui->aliveHostsTextEdit->append("以下主机已开启");
    for (const QString &host : aliveHosts) {
        ui->aliveHostsTextEdit->append(host);
    }
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
