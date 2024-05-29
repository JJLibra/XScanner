#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "portscannerwindow.h"
#include "hostscannerwindow.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_scanHostsButton_clicked();
    void on_scanPortsButton_clicked();

private:
    Ui::MainWindow *ui;
    PortScannerWindow *portScannerWindow;
    HostScannerWindow *hostScannerWindow;
};

#endif // MAINWINDOW_H
