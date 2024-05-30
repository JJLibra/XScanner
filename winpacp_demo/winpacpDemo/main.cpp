#include "mainwindow.h"

#include <QApplication>
#include <QDebug>
#include "pcap.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();


    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        qDebug() << errbuf;
    }
    for(d = alldevs; d; d = d->next)
    {
        qDebug() << ++i << d->name;
        if(d->description)
            qDebug() << d->description;
        else
            qDebug("(No description available)");
    }
    if(i == 0)
    {
        qDebug("No interfaces found! Make sure WinPcap is installed.");
    }
    pcap_freealldevs(alldevs);


    return a.exec();
}

