#include "mainwindow.h"
#include <QApplication>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <QDebug>
#include <QSplashScreen>
#include <QMovie>
#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>
#include <QFile>

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
    mainWindow.setWindowIcon(QIcon(":/xxfer.jpg"));

    QFile qssFile(":/1.qss");
    if(qssFile.open(QFile::ReadOnly)){
        a.setStyleSheet(qssFile.readAll());
    }
    qssFile.close();

    //主程序淡入
    QPropertyAnimation *animation2 = new QPropertyAnimation(&w,"windowOpacity");
    animation2->setDuration(300);
    animation2->setStartValue(0);
    animation2->setEndValue(1);
    animation2->start();
    w.show();

    int result = a.exec();

    WSACleanup();

    return result;
}
