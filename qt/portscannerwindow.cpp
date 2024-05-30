#include "portscannerwindow.h"
#include "ui_portscannerwindow.h"
#include <QTcpSocket>
#include <QThread>
#include <QDebug>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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
    : QMainWindow(parent), ui(new Ui::PortScannerWindow), activeScans(0)
{
    ui->setupUi(this);

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
    scanType = static_cast<ScanType>(ui->scanTypeComboBox->currentIndex());

    if (ipAddress.isEmpty() || startPort <= 0 || endPort <= 0 || startPort > endPort) {
        ui->resultTextEdit->append("错误输入");
        return;
    }

    // 初始化
    ui->resultTextEdit->clear();
    currentPort = startPort;
    totalPorts = endPort - startPort + 1;
    activeScans = 0;

    ui->resultTextEdit->append("正在扫描...");
    for (int i = 0; i < 20 && currentPort <= endPort; ++i) {
        startPortScan();
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

        connect(thread, &QThread::started, worker, &PortScannerWorker::startScan);
        connect(worker, &PortScannerWorker::portScanFinished, this, &PortScannerWindow::handlePortScanResult);
        connect(worker, &PortScannerWorker::portScanFinished, thread, &QThread::quit);
        connect(worker, &PortScannerWorker::portScanFinished, worker, &PortScannerWorker::deleteLater);
        connect(thread, &QThread::finished, thread, &QThread::deleteLater);

        thread->start();
    }
}

void PortScannerWindow::handlePortScanResult(const QString &ip, int port, bool isOpen, const QString &service, bool isFiltered)
{
    activeScans--;

    if (isOpen || scanType == UDPScan) {
        if (isOpen) {
            if (isFiltered) {
                ui->resultTextEdit->append(QString("Port %1 is open|filtered (%2)").arg(port).arg(service));
            } else {
                ui->resultTextEdit->append(QString("Port %1 is open (%2)").arg(port).arg(service));
            }
        } else if (scanType == UDPScan) {
            ui->resultTextEdit->append(QString("Port %1 is open|filtered (%2)").arg(port).arg(service));
        }
    }

    int progress = ((currentPort - startPort) * 100) / totalPorts;
    updateProgress(progress);

    if (currentPort <= endPort) {
        startPortScan();
    }

    if (activeScans == 0 && currentPort > endPort) {
        ui->resultTextEdit->append("端口扫描已完成");
    }
}

void PortScannerWindow::updateProgress(int value)
{
    ui->progressBar->setValue(value);
}

QString PortScannerWindow::identifyService(int port)
{
    return commonPorts.value(port, "Unknown");
}

PortScannerWorker::PortScannerWorker(const QString &ip, int port, PortScannerWindow::ScanType scanType, PortScannerWindow *scannerWindow, QObject *parent)
    : QObject(parent), ipAddress(ip), port(port), scanType(scanType), scannerWindow(scannerWindow)
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

bool PortScannerWorker::send_syn_packet(const char *packet, int packet_len, struct sockaddr_in *target)
{
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == INVALID_SOCKET) {
        qDebug() << "Failed to create raw socket, error:" << WSAGetLastError();
        return false;
    }

    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&optval, sizeof(optval)) == SOCKET_ERROR) {
        qDebug() << "Failed to set socket options, error:" << WSAGetLastError();
        closesocket(sock);
        return false;
    }

    int sent_bytes = sendto(sock, packet, packet_len, 0, (struct sockaddr *)target, sizeof(*target));
    if (sent_bytes == SOCKET_ERROR) {
        qDebug() << "Failed to send packet, error:" << WSAGetLastError();
        closesocket(sock);
        return false;
    }

    bool result = receive_response(sock, target);

    closesocket(sock);
    return result;
}

QString PortScannerWorker::getLocalIPAddress() {
    const QHostAddress &localhost = QHostAddress(QHostAddress::LocalHost);
    for (const QHostAddress &address : QNetworkInterface::allAddresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol && address != localhost)
            return address.toString();
    }
    return QString();
}

bool PortScannerWorker::receive_response(SOCKET sock, struct sockaddr_in *target) {
    char buffer[4096];
    struct sockaddr_in from;
    int fromlen = sizeof(from);

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (select(0, &readfds, NULL, NULL, &timeout) > 0) {
        int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &fromlen);
        if (bytes_received > 0) {
            struct ip *iph = (struct ip *)buffer;
            struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ip_hl * 4);
            if (from.sin_addr.s_addr == target->sin_addr.s_addr) {
                if (tcph->th_flags & TH_RST) {
                    qDebug() << "Received RST packet. Port is closed.";
                    return false;
                } else if (tcph->th_flags & TH_SYN && tcph->th_flags & TH_ACK) {
                    qDebug() << "Received SYN-ACK packet. Port is open.";
                    return true;
                }
            }
        }
    }
    qDebug() << "No response received for SYN packet.";
    return false;
}

bool PortScannerWorker::decode_icmp_response(char *buffer, int packet_size, DECODE_RESULT &decode_result) {
    IP_HEADER *ip_header = (IP_HEADER *)buffer;
    int ip_header_len = ip_header->hdr_len * 4;
    if (packet_size < (int)(ip_header_len + sizeof(icmp_header))) {
        qDebug() << "Error: packet size too short";
        return false;
    }

    icmp_header *icmp_hdr = (icmp_header *)(buffer + ip_header_len);
    decode_result.code = icmp_hdr->code;
    decode_result.type = icmp_hdr->type;
    decode_result.port = ntohs(*(u_short *)(buffer + 20 + 8 + 20 + 2));
    decode_result.dwIPaddr.S_un.S_addr = ip_header->sourceIP;

    return (icmp_hdr->type == 3 && icmp_hdr->code == 3);
}

bool PortScannerWorker::udp_receive_response(SOCKET sock, struct sockaddr_in *target, bool &isFiltered) {
    char buffer[4096];
    struct sockaddr_in from;
    int fromlen = sizeof(from);

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;

    if (select(0, &readfds, NULL, NULL, &timeout) > 0) {
        int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &fromlen);
        if (bytes_received > 0) {
            qDebug() << "Received ICMP message. Raw data:" << QByteArray(buffer, bytes_received).toHex();
            DECODE_RESULT decode_result;
            if (decode_icmp_response(buffer, bytes_received, decode_result)) {
                if (decode_result.dwIPaddr.s_addr == target->sin_addr.s_addr && decode_result.port == target->sin_port) {
                    qDebug() << "Received ICMP port unreachable message for port" << ntohs(target->sin_port);
                    isFiltered = false;
                    return false;
                } else {
                    qDebug() << "Received ICMP message from different address or port.";
                }
            } else {
                qDebug() << "Received unexpected ICMP message.";
                isFiltered = true;
            }
        } else {
            qDebug() << "No response received for UDP packet.";
            isFiltered = true;
        }
    } else {
        qDebug() << "UDP select timeout.";
        isFiltered = true;
    }
    return true;
}

void PortScannerWorker::startScan()
{
    bool isOpen = false;
    bool isFiltered = false;

    QHostAddress address(ipAddress);
    if (address.isNull()) {
        emit portScanFinished(ipAddress, port, false, "Invalid IP", isFiltered);
        return;
    }

    qDebug() << "Resolved IP Address:" << address.toString();

    if (scanType == PortScannerWindow::UDPScan) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            qDebug() << "Failed to create UDP socket, error:" << WSAGetLastError();
            emit portScanFinished(ipAddress, port, false, "UDP Socket Error", isFiltered);
            return;
        }

        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = inet_addr(ipAddress.toStdString().c_str());
        target.sin_port = htons(port);

        char data[] = "Test Data";
        int sent_bytes = sendto(sock, data, sizeof(data), 0, (struct sockaddr *)&target, sizeof(target));
        if (sent_bytes == SOCKET_ERROR) {
            qDebug() << "Failed to send UDP packet, error:" << WSAGetLastError();
            closesocket(sock);
            emit portScanFinished(ipAddress, port, false, "UDP Send Error", isFiltered);
            return;
        }

        qDebug() << "UDP packet sent to" << ipAddress << "port" << port;

        isOpen = udp_receive_response(sock, &target, isFiltered);

        closesocket(sock);
    } else if (scanType == PortScannerWindow::SYNscan) {
        QString localIPAddress = getLocalIPAddress();
        if (localIPAddress.isEmpty()) {
            qDebug() << "Failed to get local IP address.";
            emit portScanFinished(ipAddress, port, false, "Local IP Error", isFiltered);
            return;
        }

        struct sockaddr_in source, target;
        source.sin_family = AF_INET;
        source.sin_addr.s_addr = inet_addr(localIPAddress.toStdString().c_str());
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = inet_addr(ipAddress.toStdString().c_str());
        target.sin_port = htons(port);

        char packet[4096];
        memset(packet, 0, 4096);
        create_syn_packet(packet, &target, &source);

        if (send_syn_packet(packet, sizeof(struct ip) + sizeof(struct tcphdr), &target)) {
            qDebug() << "SYN packet sent successfully.";
            isOpen = true;
        } else {
            qDebug() << "Failed to send SYN packet.";
        }
    } else if (scanType == PortScannerWindow::FINscan) {
        // FIN scan implementation can be added here
    } else if (scanType == PortScannerWindow::ACKscan) {
        // ACK scan implementation can be added here
    } else {
        QTcpSocket socket;
        socket.connectToHost(address, port);
        if (socket.waitForConnected(100)) {
            isOpen = true;
            socket.disconnectFromHost();
        }
        socket.close();
    }

    QString service = isOpen ? scannerWindow->identifyService(port) : "";
    emit portScanFinished(ipAddress, port, isOpen, service, isFiltered);
}
