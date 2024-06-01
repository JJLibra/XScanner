#ifndef PORTSCANNERWINDOW_H
#define PORTSCANNERWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QTcpSocket>
#include <QMap>
#include <QUdpSocket>
#include <QNetworkInterface>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <QElapsedTimer>

QT_BEGIN_NAMESPACE
namespace Ui { class PortScannerWindow; }
QT_END_NAMESPACE

class PortScannerWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit PortScannerWindow(QWidget *parent = nullptr);
    ~PortScannerWindow();
    QString identifyService(int port);

    enum ScanType { // 供选择的扫描类型
        QuickScan,
        TCPScan,
        SYNscan,
        FINscan,
        ACKscan,
        UDPScan
    };

private slots:
    void on_startButton_clicked();
    void handlePortScanResult(const QString &ip, int port, bool isOpen, const QString &service, bool isFiltered);
    void updateProgress(int value);
    void populateNetworkInterfaces();
    void on_saveLogButton_clicked();

private:
    Ui::PortScannerWindow *ui;
    void startPortScan();

    QString ipAddress;
    int startPort;
    int endPort;
    int currentPort;
    int totalPorts;
    int activeScans;
    int threadNum = 50;
    QMap<int, QString> commonPorts;
    ScanType scanType;
    QString selectedInterface;
    int udpFilteredPortNum = 0;
    int openPortNum = 0;
    QList<int> commonPortList; // 常见端口列表
    QElapsedTimer timer;
};

class PortScannerWorker : public QObject
{
    Q_OBJECT

public:
    PortScannerWorker(const QString &ip, int port, PortScannerWindow::ScanType scanType, const QString &selectedInterface, PortScannerWindow *scannerWindow, QObject *parent = nullptr);
    void startScan();

signals:
    void portScanFinished(const QString &ip, int port, bool isOpen, const QString &service, bool isFiltered);

private:
    bool isFiltered = false;

    QString ipAddress;
    int port;
    PortScannerWindow::ScanType scanType;
    QString selectedInterface;
    PortScannerWindow *scannerWindow;

    // SYN 扫描
    unsigned short checksum(void *b, int len);
    void create_syn_packet(char *packet, struct sockaddr_in *target, struct sockaddr_in *source);
    void create_ack_packet(char *packet, struct sockaddr_in *target, struct sockaddr_in *source);
    bool send_packet(const char *packet, int packet_len, struct sockaddr_in *target);
    QString getLocalIPAddress();
    bool receive_response(pcap_t *handle, struct sockaddr_in *target);
    bool udp_receive_response(QUdpSocket &udpSocket, const QHostAddress &target, quint16 targetPort);
    bool decode_icmp_response(char *buffer, int packet_size, struct DECODE_RESULT &decode_result);
    QString fingerprintService(int port); // Todo 参考namp（指纹识别）：精确端口服务
};

// 参照状态码
struct DECODE_RESULT {
    unsigned int port;
    in_addr dwIPaddr;
    BYTE code;
    BYTE type; // ICMP 类型
};

// IP 头
struct IP_HEADER {
    unsigned char hdr_len:4; // 头长
    unsigned char version:4; // 版本
    unsigned char tos; // 服务类型
    unsigned short total_len; // 总长
    unsigned short identifier; // 标识
    unsigned short frag_and_flags; // 标记 flag
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum; // 校验
    unsigned long sourceIP;
    unsigned long destIP;
};

// ICMP 报文头
struct icmp_header {
    BYTE type; // 消息类型
    BYTE code;
    USHORT checksum;
    USHORT id;
    USHORT seq;
};

#endif // PORTSCANNERWINDOW_H
