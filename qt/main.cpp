#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;

    QMainWindow mainWindow;
    mainWindow.setWindowIcon(QIcon(":/xxfer.ico"));

    w.show();
    return a.exec();
}
