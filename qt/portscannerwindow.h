#ifndef PORTSCANNERWINDOW_H
#define PORTSCANNERWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QTcpSocket>
#include <QMap>
#include <QUdpSocket>

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
        UDPScan
    };

private slots:
    void on_startButton_clicked();
    void handlePortScanResult(const QString &ip, int port, bool isOpen, const QString &service);
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
    void portScanFinished(const QString &ip, int port, bool isOpen, const QString &service);

private:
    QString ipAddress;
    int port;
    PortScannerWindow::ScanType scanType;
    PortScannerWindow *scannerWindow;
};

#endif // PORTSCANNERWINDOW_H
