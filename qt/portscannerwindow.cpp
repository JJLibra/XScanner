#include "portscannerwindow.h"
#include "ui_portscannerwindow.h"
#include <QTcpSocket>
#include <QThread>
#include <QDebug>

PortScannerWindow::PortScannerWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::PortScannerWindow), activeScans(0)
{
    ui->setupUi(this);

    // 常见服务端口
    commonPorts.insert(80, "HTTP");
    commonPorts.insert(443, "HTTPS");
    commonPorts.insert(21, "FTP");
    commonPorts.insert(22, "SSH");
    commonPorts.insert(23, "Telnet");
    commonPorts.insert(25, "SMTP");
}

PortScannerWindow::~PortScannerWindow()
{
    delete ui;
}

void PortScannerWindow::on_startButton_clicked()
{
    ipAddress = ui->ipLineEdit->text();
    startPort = ui->startPortLineEdit->text().toInt();
    endPort = ui->endPortLineEdit->text().toInt();
    scanType = static_cast<ScanType>(ui->scanTypeComboBox->currentIndex()); // 选择扫描方式：Quick/All/TCP/UDP

    if (ipAddress.isEmpty() || startPort <= 0 || endPort <= 0 || startPort > endPort) {
        ui->resultTextEdit->append("错误输入");
        return;
    }

    // 初始化
    ui->resultTextEdit->clear();
    currentPort = startPort;
    totalPorts = endPort - startPort + 1;
    activeScans = 0;

    for (int i = 0; i < 20 && currentPort <= endPort; ++i) { // 多线程（20）
        startPortScan(); // 开扫
    }
}

void PortScannerWindow::startPortScan()
{
    if (currentPort <= endPort) {
        int port = currentPort++;
        activeScans++;

        PortScannerWorker *worker = new PortScannerWorker(ipAddress, port, scanType, this);
        QThread *thread = new QThread;
        worker->moveToThread(thread);

        // 线程管理
        connect(thread, &QThread::started, worker, &PortScannerWorker::startScan);
        connect(worker, &PortScannerWorker::portScanFinished, this, &PortScannerWindow::handlePortScanResult);
        connect(worker, &PortScannerWorker::portScanFinished, thread, &QThread::quit);
        connect(worker, &PortScannerWorker::portScanFinished, worker, &PortScannerWorker::deleteLater);
        connect(thread, &QThread::finished, thread, &QThread::deleteLater);

        thread->start();
    }
}

void PortScannerWindow::handlePortScanResult(const QString &ip, int port, bool isOpen, const QString &service)
{
    activeScans--;

    if (isOpen) {
        ui->resultTextEdit->append(QString("Port %1 is open (%2)").arg(port).arg(service));
    }

    int progress = ((currentPort - startPort) * 100) / totalPorts; // 更新进度
    updateProgress(progress);

    if (currentPort <= endPort) {
        startPortScan();
    }

    if (activeScans == 0 && currentPort > endPort) {
        ui->resultTextEdit->append("端口扫描已完成");
    }
}

// 更新扫描进度条
void PortScannerWindow::updateProgress(int value)
{
    ui->progressBar->setValue(value);
}

// 识别常见服务
QString PortScannerWindow::identifyService(int port)
{
    return commonPorts.value(port, "Unknown");
}

PortScannerWorker::PortScannerWorker(const QString &ip, int port, PortScannerWindow::ScanType scanType, PortScannerWindow *scannerWindow, QObject *parent)
    : QObject(parent), ipAddress(ip), port(port), scanType(scanType), scannerWindow(scannerWindow)
{
}

void PortScannerWorker::startScan()
{
    bool isOpen = false;

    if (scanType == PortScannerWindow::UDPScan) {
        QUdpSocket socket;
        socket.connectToHost(ipAddress, port);
        isOpen = socket.waitForConnected(100);
        socket.close();
    } else {
        QTcpSocket socket;
        socket.connectToHost(ipAddress, port);
        isOpen = socket.waitForConnected(100);
        socket.close();
    }

    QString service = isOpen ? scannerWindow->identifyService(port) : "";
    emit portScanFinished(ipAddress, port, isOpen, service);
}
