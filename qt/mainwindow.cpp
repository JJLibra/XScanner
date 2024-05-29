#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "portscannerwindow.h"
#include "hostscannerwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , portScannerWindow(new PortScannerWindow(this))
    , hostScannerWindow(new HostScannerWindow(this))
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
