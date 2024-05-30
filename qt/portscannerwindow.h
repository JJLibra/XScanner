#ifndef PORTSCANNERWINDOW_H
#define PORTSCANNERWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QTcpSocket>
#include <QMap>
#include <QUdpSocket>
#include <QNetworkInterface>
#include <winsock2.h>
#include <ws2tcpip.h>

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

    enum ScanType {
        QuickScan,
        FullScan,
        TCPScan,
        UDPScan,
        SYNscan
    };

private slots:
    void on_startButton_clicked();
    void handlePortScanResult(const QString &ip, int port, bool isOpen, const QString &service, bool isFiltered);
    void updateProgress(int value);

private:
    Ui::PortScannerWindow *ui;
    void startPortScan();

    QString ipAddress;
    int startPort;
    int endPort;
    int currentPort;
    int totalPorts;
    int activeScans;
    QMap<int, QString> commonPorts;
    ScanType scanType;
};

class PortScannerWorker : public QObject
{
    Q_OBJECT

public:
    PortScannerWorker(const QString &ip, int port, PortScannerWindow::ScanType scanType, PortScannerWindow *scannerWindow, QObject *parent = nullptr);
    void startScan();

signals:
    void portScanFinished(const QString &ip, int port, bool isOpen, const QString &service, bool isFiltered);

private:
    QString ipAddress;
    int port;
    PortScannerWindow::ScanType scanType;
    PortScannerWindow *scannerWindow;

    // SYN scan helper functions
    unsigned short checksum(void *b, int len);
    void create_syn_packet(char *packet, struct sockaddr_in *target, struct sockaddr_in *source);
    bool send_syn_packet(const char *packet, int packet_len, struct sockaddr_in *target);
    QString getLocalIPAddress();
    bool receive_response(SOCKET sock, struct sockaddr_in *target);
    bool udp_receive_response(SOCKET sock, struct sockaddr_in *target, bool &isFiltered);
    bool decode_icmp_response(char *buffer, int packet_size, struct DECODE_RESULT &decode_result);
};

// Define DECODE_RESULT structure
struct DECODE_RESULT {
    UINT port; // Port number
    in_addr dwIPaddr; // IP address
    BYTE code; // ICMP code
    BYTE type; // ICMP type
};

// Define IP header structure
struct IP_HEADER {
    unsigned char hdr_len:4; // Header length
    unsigned char version:4; // Version
    unsigned char tos; // Type of service
    unsigned short total_len; // Total length
    unsigned short identifier; // Identification
    unsigned short frag_and_flags; // Flags and fragment offset
    unsigned char ttl; // Time to live
    unsigned char protocol; // Protocol
    unsigned short checksum; // Checksum
    unsigned long sourceIP; // Source address
    unsigned long destIP; // Destination address
};

// Define ICMP header structure
struct icmp_header {
    BYTE type; // ICMP message type
    BYTE code; // ICMP message code
    USHORT checksum; // ICMP checksum
    USHORT id; // ICMP identifier
    USHORT seq; // ICMP sequence number
};

#endif // PORTSCANNERWINDOW_H
