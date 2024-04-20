// MainWindow.cpp
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "dialog.h"
#include "infopacet.h"
#include <QMessageBox>
#include <QFileDialog>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this); //инициализация интерфейса




    QMessageBox messageBox;
    messageBox.setWindowTitle("Информация");
    messageBox.setIcon(QMessageBox::Warning);
    messageBox.setText("Внимание! Это частная программа /12 учебной группы. Ее копирование без разрешения собственника (Г.Р.) запрещено. Все права защищены. Вся несанкционированная копия или распространение этой программы может повлечь юридические последствия. Пожалуйста, используйте эту программу только в рамках образца.");
    messageBox.exec();
    messageBox.move(this->geometry().center() - messageBox.rect().center());    //Попытался вывести в центре, не получилось



}

MainWindow::~MainWindow()
{
    delete ui;                             //деструктор
}




void MainWindow::on_action_triggered() //метод реализации #include <QFileDialog>
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Открыть файл"), QDir::homePath(), tr("Файлы PCAP (*.pcap);;Файлы PCAPNG (*.pcapng)"));

    if (!fileName.isEmpty()) {
        // Устанавливаем текст в статус баре
        ui->statusbar->showMessage("Открыт файл: " + fileName);



        // Вызываем функцию для анализа pcapng файла
        readPcapngFile(fileName);
    }
}




void MainWindow::readPcapngFile(const QString &fileName)
{
    char errbuf[PCAP_ERRBUF_SIZE]; //массив для хранения ошибок
    pcap_t *pcap = pcap_open_offline(fileName.toStdString().c_str(), errbuf);//открывает файлы захвата

    struct pcap_pkthdr header; //хранения заголовка пакета.
    const u_char *packet; //хранение данных пактеа
    while ((packet = pcap_next(pcap, &header)) != nullptr) {//пока pcap_next не вернет пустой указатель
        // Анализ заголовка
        const struct ether_header *ethHeader = (struct ether_header*) packet; //packet содержит данные пакета, а ether_header определена в библиотеке netinet/if_ether.h и содержит информацию о заголовке Ethernet-кадра.
        int etherType = ntohs(ethHeader->ether_type); //считывает значение поля ether_type из заголовка Ethernet и сохраняет его в переменной etherType
        /*ntohs используется для преобразования порядка байт в сетевой порядок (Big-Endian)*/
        QString protocol;//хранит протокол
        QString source;//хранит адрес источника
        QString destination;//хранит адрес приемника
        int size = header.len; //хранит размер пакета

        if (etherType == ETHERTYPE_IP) {
            // IPv4 пакет
            const struct ip *ipHeader = (struct ip*)(packet + sizeof(struct ether_header));//извлекает указатель ipHeader на структуру ip, которая содержит информацию о заголовке IPv4 пакета. Вычеслеие начала заголовка ip
            source = QString::fromStdString(inet_ntoa(ipHeader->ip_src));//извлечение отправителя IP (ip_src) из заголовка IPv4, преобразовывание его в строку inet_ntoa
            destination = QString::fromStdString(inet_ntoa(ipHeader->ip_dst));//извлечение приемника IP (ip_dst) из заголовка IPv4, преобразовывание его в строку inet_ntoa
            int ipProtocol = ipHeader->ip_p;// достает значение протокола из ipv4 и определяет тип протокола
            if (ipProtocol == IPPROTO_TCP) {
                protocol = "IPv4/TCP";
            } else if (ipProtocol == IPPROTO_UDP) {
                protocol = "IPv4/UDP";
                // Дополнительно анализируем UDP пакеты
                const struct udphdr *udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                /*вычисляем смещение от начала пакета до заголовка UDP, добавляя размеры заголовков Ethernet и IPv4.*/

                int srcPort = ntohs(udpHeader->uh_sport);
                int dstPort = ntohs(udpHeader->uh_dport);
                /*Функция ntohs используется для преобразования значения из сетевого порядка байтов в хостовый порядок байтов.*/

                if (srcPort == 53 || dstPort == 53) {
                    protocol = "IPv4/DNS";
                }
            } else if (ipProtocol == IPPROTO_ICMP) {
                protocol = "IPv4/ICMP";
            } else {
                protocol = "IPv4/Other";
            }
        } else if (etherType == ETHERTYPE_ARP) {
            protocol = "ARP";
        } else if (etherType == ETHERTYPE_IPV6) {
            // IPv6 пакет

            const struct ip6_hdr *ip6Header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
            uint8_t nextHeader = ip6Header->ip6_nxt;
            if (nextHeader == IPPROTO_TCP) {
                protocol = "IPv6/TCP";
            } else if (nextHeader == IPPROTO_UDP) {
                protocol = "IPv6/UDP";
            } else if (nextHeader == IPPROTO_ICMPV6) {
                protocol = "IPv6/ICMPv6";
            } else {
                protocol = "IPv6/Other";
            }
        }


        // Добавляем информацию в QListWidget
        QListWidgetItem *item = new QListWidgetItem;
        item->setText(QString("Протокол: %1, Источник: %2, Приемник: %3, Размер: %4 байт").arg(protocol, source, destination, QString::number(size)));
        if (protocol == "IPv4/TCP") {
            item->setForeground(Qt::blue);
        } else if (protocol == "IPv4/UDP") {
            item->setForeground(Qt::green);
        } else if (protocol == "IPv4/DNS") {
            item->setForeground(Qt::red);
        } else if (protocol == "IPv4/Other" || protocol == "Other") {
            item->setForeground(Qt::black);
        }
        ui->listWidget->addItem(item);
    }

    pcap_close(pcap);
}

void MainWindow::on_listWidget_currentItemChanged(QListWidgetItem *current, QListWidgetItem *previous)
{

}

void MainWindow::on_pushButton_clicked()
{
    Dialog window;
    window.setModal(true);   //Вывод инфы про протоколы
    window.exec();
}

void MainWindow::on_lineEdit_textChanged(const QString &text)
{
    filterPackets(text);
}
void MainWindow::on_listWidget_itemDoubleClicked(QListWidgetItem *item)
{
    // Получаем информацию о пакете
    QString packetInfo = item->text();

    // Создаем экземпляр диалога Infopacet
    Infopacet *infoPacketDialog = new Infopacet(this);

    // Устанавливаем информацию о пакете в диалог
    infoPacketDialog->setPacketInfo(packetInfo);

    // Открываем диалог
    infoPacketDialog->exec();
}


void MainWindow::filterPackets(const QString &text)       //Реализация фильтра
{
    for (int i = 0; i < ui->listWidget->count(); ++i) {
        QListWidgetItem *item = ui->listWidget->item(i);
        if (item->text().contains(text, Qt::CaseInsensitive)) {
            item->setHidden(false);
        } else {
            item->setHidden(true);
        }
    }
}

