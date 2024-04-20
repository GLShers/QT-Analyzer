// infopacet.h
#ifndef INFOPACET_H
#define INFOPACET_H

#include <QDialog>

namespace Ui {
class Infopacet;
}

class Infopacet : public QDialog
{
    Q_OBJECT

public:
    explicit Infopacet(QWidget *parent = nullptr);
    ~Infopacet();
    void setPacketInfo(const QString &packetInfo);

private slots:
    void on_labelPacketInfo_linkActivated(const QString &link);

private:
    Ui::Infopacet *ui;
};

#endif // INFOPACET_H
