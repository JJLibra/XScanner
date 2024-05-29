#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "portscannerwindow.h"
#include "hostscannerwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , portScannerWindow(new PortScannerWindow(this))  //端口扫描
    , hostScannerWindow(new HostScannerWindow(this))  //扫描存活主机
{
    ui->setupUi(this);
    connect(ui->scanHostsButton, &QPushButton::clicked, this, &MainWindow::on_scanHostsButton_clicked);
    connect(ui->scanPortsButton, &QPushButton::clicked, this, &MainWindow::on_scanPortsButton_clicked);
}

MainWindow::~MainWindow()
{
    delete ui;
    delete portScannerWindow;
    delete hostScannerWindow;
}

void MainWindow::on_scanHostsButton_clicked()
{
    hostScannerWindow->show();
}

void MainWindow::on_scanPortsButton_clicked()
{
    portScannerWindow->show();
}
