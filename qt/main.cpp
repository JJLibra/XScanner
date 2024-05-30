#include "mainwindow.h"
#include <QApplication>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <QDebug>

int main(int argc, char *argv[])
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        qDebug() << "Failed to initialize Winsock";
        return 1;
    }

    QApplication a(argc, argv);
    MainWindow w;

    QMainWindow mainWindow;
    mainWindow.setWindowIcon(QIcon(":/xxfer.ico"));

    w.show();
    int result = a.exec();

    WSACleanup();

    return result;
}
