#include "infopacet.h"
#include "ui_infopacet.h"

Infopacet::Infopacet(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Infopacet)
{
    ui->setupUi(this);

    // Подключаем сигнал linkActivated к слоту on_labelPacketInfo_linkActivated
    connect(ui->labelPacketInfo, SIGNAL(linkActivated(QString)), this, SLOT(on_labelPacketInfo_linkActivated(QString)));
}

Infopacet::~Infopacet()
{
    delete ui;
}

void Infopacet::setPacketInfo(const QString &packetInfo)
{
    // Очищаем все предыдущие виджеты из Layout
    QLayoutItem *item;
    while ((item = ui->verticalLayout->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }

    // Парсим строку с информацией о пакете
    QStringList packetAttributes = packetInfo.split(", ");
    for (const QString &attribute : packetAttributes) {
        // Делим атрибут на ключ и значение
        QStringList parts = attribute.split(": ");
        if (parts.size() == 2) {
            QString key = parts[0];
            QString value = parts[1];

            // Создаем новый QLabel для отображения атрибута пакета
            QLabel *label = new QLabel(this);
            label->setText(key + ": " + value);
            // Добавляем QLabel в вертикальный Layout
            ui->verticalLayout->addWidget(label);
        }
    }
}




void Infopacet::on_labelPacketInfo_linkActivated(const QString &link)
{
    // Ваша обработка активации ссылки
}
