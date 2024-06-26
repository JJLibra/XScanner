#include "portscannerwindow.h"
#include "ui_portscannerwindow.h"
#include <QTcpSocket>
#include <QThread>
#include <QDebug>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <QElapsedTimer>
#include <QFileDialog>
#include <QTimer>

struct ip {
    unsigned char  ip_hl:4;
    unsigned char  ip_v:4;
    unsigned char  ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    unsigned char  ip_ttl;
    unsigned char  ip_p;
    unsigned short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

struct tcphdr {
    u_short th_sport;
    u_short th_dport;
    u_int th_seq;
    u_int th_ack;
    u_char th_offx2;
    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

struct pseudo_header {
    u_int src_addr;
    u_int dst_addr;
    u_char zero;
    u_char protocol;
    u_short length;
};

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

PortScannerWindow::PortScannerWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::PortScannerWindow), activeScans(0), threadNum(50), tcpDelay(100), commonPortsIterator(commonPorts.constEnd()), scannedPortsCount(0), stopRequested(false)
{
    ui->setupUi(this);
    ui->progressBar->setValue(0);
    ui->progressBar->setRange(0, 100);  // 进度条的范围从0到100

    // 目前使用常见端口-服务映射表确定端口服务
    commonPorts.insert(21, "FTP");
    commonPorts.insert(22, "SSH");
    commonPorts.insert(23, "Telnet");
    commonPorts.insert(25, "SMTP");
    commonPorts.insert(53, "DNS");
    commonPorts.insert(80, "HTTP");
    commonPorts.insert(110, "POP3");
    commonPorts.insert(119, "NNTP");
    commonPorts.insert(143, "IMAP");
    commonPorts.insert(161, "SNMP");
    commonPorts.insert(443, "HTTPS");
    commonPorts.insert(445, "Microsoft-DS");
    commonPorts.insert(993, "IMAPS");
    commonPorts.insert(995, "POP3S");
    commonPorts.insert(1080, "SOCKS");
    commonPorts.insert(1433, "MSSQL");
    commonPorts.insert(1723, "PPTP");
    commonPorts.insert(3306, "MySQL");
    commonPorts.insert(3389, "RDP");
    commonPorts.insert(5900, "VNC");
    commonPorts.insert(8080, "HTTP-Proxy");

    ui->threadNumSpinBox->setValue(threadNum);
    ui->tcpDelaySpinBox->setValue(tcpDelay);

    populateNetworkInterfaces(); // 查找可使用的网络接口
}

PortScannerWindow::~PortScannerWindow()
{
    delete ui;
}

int PortScannerWindow::getTcpDelay() const {
    return tcpDelay;
}

void PortScannerWindow::on_stopButton_clicked()
{
    stopRequested = true;
    ui->resultTextEdit->append("扫描已停止。");
}

void PortScannerWindow::on_saveLogButton_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("保存日志"), "", tr("文本文件 (*.txt)"));
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << "目标 IP: " << ipAddress << "\n";
            out << "起始端口: " << startPort << "\n";
            out << "终止端口: " << endPort << "\n";
            out << "扫描模式: " << ui->scanTypeComboBox->currentText() << "\n\n";
            out << ui->resultTextEdit->toPlainText();
            file.close();
            ui->resultTextEdit->append("日志已成功保存至 " + fileName);
        } else {
            ui->resultTextEdit->append("无法保存日志文件。");
        }
    }
}

void PortScannerWindow::populateNetworkInterfaces()
{
    ui->interfaceComboBox->clear();
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug() << "接口获取错误，错误原因: " << errbuf;
        return;
    }

    for (pcap_if_t *d = alldevs; d; d = d->next) {
        ui->interfaceComboBox->addItem(d->name);
    }

    pcap_freealldevs(alldevs);
}

void PortScannerWindow::on_startButton_clicked()
{
    ipAddress = ui->ipLineEdit->text();
    startPort = ui->startPortLineEdit->text().toInt();
    endPort = ui->endPortLineEdit->text().toInt();
    scanType = static_cast<ScanType>(ui->scanTypeComboBox->currentIndex());
    selectedInterface = ui->interfaceComboBox->currentText();

    if (ipAddress.isEmpty() || startPort <= 0 || endPort <= 0 || startPort > endPort) {
        ui->resultTextEdit->append("错误输入，请检查输入内容~");
        return;
    }

    stopRequested = false;
    threadNum = ui->threadNumSpinBox->value();
    tcpDelay = ui->tcpDelaySpinBox->value();

    // 初始化
    ui->resultTextEdit->clear();
    currentPort = startPort;
    totalPorts = (scanType == QuickScan) ? commonPorts.size() : (endPort - startPort + 1);
    activeScans = 0; // 活动扫描数
    openPortNum = 0; // 开放端口数
    udpFilteredPortNum = 0; // UDP Filtered 端口数
    scannedPortsCount = 0; // 初始化已经扫描的端口数量

    QString startTime = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm");
    ui->resultTextEdit->append("Starting XScanner at   " + startTime);
    ui->resultTextEdit->append("\nPORT           STATE         SERVICE");

    timer.start(); // 扫描计时器

    if (scanType == QuickScan) { // 只扫描列表中的常见端口
        commonPortsIterator = commonPorts.constBegin();
        for (int i = 0; i < threadNum && commonPortsIterator != commonPorts.constEnd(); ++i) {
            startPortScan();
        }
    } else {
        for (int i = 0; i < threadNum && currentPort <= endPort; ++i) {
            startPortScan();
        }
    }
}

void PortScannerWindow::startPortScan()
{
    if (stopRequested) {
        return;
    }

    if (scanType == QuickScan) {
        if (commonPortsIterator != commonPorts.constEnd()) {
            int port = commonPortsIterator.key();
            ++commonPortsIterator;
            ++scannedPortsCount;
            activeScans++;

            PortScannerWorker *worker = new PortScannerWorker(ipAddress, port, scanType, selectedInterface, this); //扫描器核心逻辑
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
    } else {
        if (currentPort <= endPort) {
            int port = currentPort++;
            activeScans++;

            PortScannerWorker *worker = new PortScannerWorker(ipAddress, port, scanType, selectedInterface, this); //扫描器核心逻辑
            QThread *thread = new QThread;
            worker->moveToThread(thread);

            // 线程管理
            connect(thread, &QThread::started, worker, &PortScannerWorker::startScan);
            connect(worker, &PortScannerWorker::portScanFinished, this, &PortScannerWindow::handlePortScanResult);
            connect(worker, &PortScannerWorker::portScanFinished, thread, &QThread::quit);
            connect(worker, &PortScannerWorker::portScanFinished, worker, &PortScannerWorker::deleteLater);
            connect(thread, &QThread::finished, thread, &QThread::deleteLater);

            thread->start();

            if (activeScans % threadNum == 0 && scanType == PortScannerWindow::UDPScan) {
                QThread::msleep(5); // 设置延时
            }
        }
    }
}

void PortScannerWindow::handlePortScanResult(const QString &ip, int port, bool isOpen, const QString &service, bool isFiltered)
{
    activeScans--;

    if (stopRequested) {
        return;
    }

    if (isOpen) {
        QString result;
        if (isFiltered && scanType == PortScannerWindow::UDPScan) {
            result = QString("%1/udp").arg(port).leftJustified(10, ' ') + QString("open|filtered").leftJustified(15, ' ') + service.leftJustified(10, ' ');
            udpFilteredPortNum++;
        } else {
            result = QString("%1/tcp").arg(port).leftJustified(15, ' ') + QString("open").leftJustified(15, ' ') + service.leftJustified(10, ' ');
        }
        ui->resultTextEdit->append(result);
        openPortNum++;
    }

    // 更新进度条
    int progress;
    if (scanType == QuickScan) {
        progress = (scannedPortsCount * 100) / totalPorts;
    } else {
        progress = ((currentPort - startPort) * 100) / totalPorts;
    }
    updateProgress(progress);

    if (scanType == QuickScan) {
        if (commonPortsIterator != commonPorts.constEnd()) {
            startPortScan();
        }
    } else {
        if (currentPort <= endPort) {
            startPortScan();
        }
    }

    if (activeScans == 0 && ((scanType != QuickScan) || (commonPortsIterator == commonPorts.constEnd())) && (currentPort > endPort)) {
        double elapsed = timer.elapsed();
        if (scanType == PortScannerWindow::UDPScan) {
            ui->resultTextEdit->append(QString("Not shown: %1 closed udp ports").arg(totalPorts - udpFilteredPortNum));
            ui->resultTextEdit->append(QString("\n共有 %1 个端口开放\n本次扫描耗时 %2 s").arg(openPortNum).arg(elapsed / 1000));
        } else {
            ui->resultTextEdit->append(QString("\n共有 %1 个端口开放\n本次扫描耗时 %2 s").arg(openPortNum).arg(elapsed / 1000));
        }
    }
}

void PortScannerWindow::updateProgress(int value)
{
    ui->progressBar->setValue(value);
}

QString PortScannerWindow::identifyService(int port)
{
    return commonPorts.value(port, "tcp"); // 暂时默认未知服务为 tcp
}

// **扫描器核心：处理器**
PortScannerWorker::PortScannerWorker(const QString &ip, int port, PortScannerWindow::ScanType scanType, const QString &selectedInterface, PortScannerWindow *scannerWindow, QObject *parent)
    : QObject(parent), ipAddress(ip), port(port), scanType(scanType), selectedInterface(selectedInterface), scannerWindow(scannerWindow)
{
}

unsigned short PortScannerWorker::checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// 创建 TCP_SYN 报文
void PortScannerWorker::create_syn_packet(char *packet, struct sockaddr_in *target, struct sockaddr_in *source) {
    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));
    struct pseudo_header psh;

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = source->sin_addr.s_addr;
    iph->ip_dst.s_addr = target->sin_addr.s_addr;
    iph->ip_sum = checksum((unsigned short *)packet, sizeof(struct ip));

    tcph->th_sport = htons(12345);
    tcph->th_dport = target->sin_port;
    tcph->th_seq = 0;
    tcph->th_ack = 0;
    tcph->th_offx2 = 0x50;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(32767);
    tcph->th_sum = 0;
    tcph->th_urp = 0;

    psh.src_addr = source->sin_addr.s_addr;
    psh.dst_addr = target->sin_addr.s_addr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = (char *)malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    tcph->th_sum = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
}

// 创建 TCP_ACK 报文
void PortScannerWorker::create_ack_packet(char *packet, struct sockaddr_in *target, struct sockaddr_in *source) {
    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));
    struct pseudo_header psh;

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = source->sin_addr.s_addr;
    iph->ip_dst.s_addr = target->sin_addr.s_addr;
    iph->ip_sum = checksum((unsigned short *)packet, sizeof(struct ip));

    tcph->th_sport = htons(12345);
    tcph->th_dport = target->sin_port;
    tcph->th_seq = 0;
    tcph->th_ack = 0;
    tcph->th_offx2 = 0x50;
    tcph->th_flags = TH_ACK;
    tcph->th_win = htons(32767);
    tcph->th_sum = 0;
    tcph->th_urp = 0;

    psh.src_addr = source->sin_addr.s_addr;
    psh.dst_addr = target->sin_addr.s_addr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = (char *)malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    tcph->th_sum = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
}

bool PortScannerWorker::send_packet(const char *packet, int packet_len, struct sockaddr_in *target)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug() << "网络接口获取错误: " << errbuf;
        return false;
    }

    // 获取选中的网络接口
    pcap_if_t *device = nullptr;
    for (d = alldevs; d; d = d->next) {
        if (selectedInterface == d->name) {
            device = d;
            break;
        }
    }

    if (device == nullptr) {
        qDebug() << "找不到所选网络接口";
        pcap_freealldevs(alldevs);
        return false;
    }

    pcap_t *handle;
    if ((handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf)) == NULL) {
        qDebug() << "无法打开 adapter" << device->name << " 不支持 WinPcap";
        pcap_freealldevs(alldevs);
        return false;
    }

    if (pcap_sendpacket(handle, (const u_char *)packet, packet_len) != 0) {
        qDebug() << "数据包发送失败: " << pcap_geterr(handle);
        pcap_freealldevs(alldevs);
        return false;
    }

    bool result = receive_response(handle, target); // 接收响应报文
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return result;
}

QString PortScannerWorker::getLocalIPAddress() { //获取本地 IP 地址
    const QHostAddress &localhost = QHostAddress(QHostAddress::LocalHost);
    for (const QHostAddress &address : QNetworkInterface::allAddresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol && address != localhost)
            return address.toString();
    }
    return QString();
}

bool PortScannerWorker::receive_response(pcap_t *handle, struct sockaddr_in *target) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;

    while ((res = pcap_next_ex(handle, &header, &pkt_data)) >= 0) {
        if (res == 0) {
            continue;
        }

        struct ip *iph = (struct ip *)(pkt_data + 14); // 跳过接口头部分，直接解析 TCP 头
        struct tcphdr *tcph = (struct tcphdr *)((u_char *)iph + (iph->ip_hl * 4));

        if (iph->ip_src.s_addr == target->sin_addr.s_addr && tcph->th_dport == htons(12345)) {
            if (tcph->th_flags & TH_RST) {
                return true;
            }
        }
    }

    if (res == -1) {
        qDebug() << "报文读取失败: " << pcap_geterr(handle);
    }

    return false;
}

bool PortScannerWorker::decode_icmp_response(char *buffer, int packet_size, DECODE_RESULT &decode_result) {
    IP_HEADER *ip_header = (IP_HEADER *)buffer;
    int ip_header_len = ip_header->hdr_len * 4;
    if (packet_size < (int)(ip_header_len + sizeof(icmp_header))) {
        qDebug() << "Error: 报文长度过短";
        return false;
    }

    icmp_header *icmp_hdr = (icmp_header *)(buffer + ip_header_len);
    decode_result.code = icmp_hdr->code;
    decode_result.type = icmp_hdr->type;
    decode_result.port = ntohs(*(u_short *)(buffer + 20 + 8 + 20 + 2));
    decode_result.dwIPaddr.S_un.S_addr = ip_header->sourceIP;

    return (icmp_hdr->type == 3 && icmp_hdr->code == 3);
}

bool PortScannerWorker::udp_receive_response(QUdpSocket &udpSocket, const QHostAddress &target, quint16 targetPort) {
    // 等待响应
    if (udpSocket.waitForReadyRead(1500)) {
        while (udpSocket.hasPendingDatagrams()) {
            QByteArray response;
            QHostAddress sender;
            quint16 senderPort;

            response.resize(udpSocket.pendingDatagramSize());
            udpSocket.readDatagram(response.data(), response.size(), &sender, &senderPort);

            if (sender == target && senderPort == targetPort) {
                qDebug() << "收到响应：" << response.toHex();
                return true;
            } else {
                IP_HEADER *ipHeader = (IP_HEADER *)response.data();
                if (ipHeader->protocol == 1) { // ICMP协议
                    icmp_header *icmpHeader = (icmp_header *)(response.data() + ipHeader->hdr_len * 4);
                    if (icmpHeader->type == 3 && icmpHeader->code == 3) {
                        qDebug() << "端口不可达：" << target.toString() << targetPort;
                        return false;
                    }
                }
            }
        }
    } else {
        qDebug() << "未收到响应，可能端口开放";
        isFiltered = true;
        return true;
    }
    return false;
}

void PortScannerWorker::startScan()
{
    if (scannerWindow->stopRequested) {
        emit portScanFinished(ipAddress, port, false, "", isFiltered);
        return;
    }

    bool isOpen = false;
    isFiltered = false;

    QHostAddress address(ipAddress);
    if (address.isNull()) {
        emit portScanFinished(ipAddress, port, false, "无效 IP", isFiltered);
        return;
    }
    qDebug() << "正在处理 IP:" << address.toString();

    switch (scanType) {
        case PortScannerWindow::UDPScan: { // UDP 扫描
            QUdpSocket udpSocket;
            if (!udpSocket.bind(QHostAddress::Any, 0)) { // 绑定到一个临时端口
                qDebug() << "UDP 绑定失败：" << udpSocket.errorString();
                break;
            }

            QByteArray data = "Test Data";
            qint64 bytesSent = udpSocket.writeDatagram(data, address, port);
            if (bytesSent == -1) {
                qDebug() << "发送 UDP 数据包失败：" << udpSocket.errorString();
            } else {
                qDebug() << "UDP 数据包已发送到" << address.toString() << "端口" << port;
                isOpen = udp_receive_response(udpSocket, address, port);
            }
            break;
        }
        case PortScannerWindow::SYNscan: { // SYN 扫描
//            QString localIPAddress = getLocalIPAddress();
//            if (localIPAddress.isEmpty()) {
//                qDebug() << "本地 IP 获取失败";
//                emit portScanFinished(ipAddress, port, false, "Local IP Error", isFiltered);
//                return;
//            }
            QTcpSocket socket;
            socket.connectToHost(address, port);
            if (socket.waitForConnected(scannerWindow->getTcpDelay())) {
                isOpen = true;
                socket.disconnectFromHost();
            }
            socket.close();
            break;
        }
        case PortScannerWindow::ACKscan: {
            QTcpSocket socket;
            socket.connectToHost(address, port);
            if (socket.waitForConnected(scannerWindow->getTcpDelay())) {
                isOpen = true;
                socket.disconnectFromHost();
            }
            socket.close();
            break;
        }
        case PortScannerWindow::FINscan: {
            QTcpSocket socket;
            socket.connectToHost(address, port);
            if (socket.waitForConnected(scannerWindow->getTcpDelay())) {
                isOpen = true;
                socket.disconnectFromHost();
            }
            socket.close();
            break;
        }
        case PortScannerWindow::QuickScan: { // Quick 扫描：使用 TCP 全连接扫描常见端口
            QTcpSocket socket;
            socket.connectToHost(address, port);
            if (socket.waitForConnected(scannerWindow->getTcpDelay())) {
                isOpen = true;
                socket.disconnectFromHost();
            }
            socket.close();
            break;
        }
        default: { // TCP 全连接扫描
            QTcpSocket socket;
            socket.connectToHost(address, port);
            if (socket.waitForConnected(scannerWindow->getTcpDelay())) {
                isOpen = true;
                socket.disconnectFromHost();
            }
            socket.close();
            break;
        }
    }

    QString service = isOpen ? scannerWindow->identifyService(port) : "";
    emit portScanFinished(ipAddress, port, isOpen, service, isFiltered);
}
