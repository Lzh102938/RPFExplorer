#pragma once

#include <QByteArray>
#include <QVector>

#include "EmbeddedScan.h"

// 0DRP 结构化表示：
//   头部：0x60 字节（原样保留 + 关键字段）
//   子资源表：+0x38 表首 / +0x40 表尾；每项 16B {u64 hash+size, u64 0x50000000|offset}
//   子资源数据：按表项 offset/size 切片
// serialize() 由结构重写已建模字段，未建模区域原样保留，可与输入做字节级比对。
class DrpFile {
public:
    bool parse(const QByteArray& data);
    QByteArray serialize() const;
    bool roundTripOk() const;

    bool valid() const { return m_valid; }
    const QByteArray& raw() const { return m_raw; }
    const QVector<DrpItem>& items() const { return m_items; }
    QByteArray header() const { return m_raw.left(0x60); }
    int tableOffset() const { return m_tableOff; }
    int tableEnd() const { return m_tableEnd; }
    quint32 field(int off) const;

private:
    QByteArray m_raw;
    QVector<DrpItem> m_items;
    int  m_tableOff = 0;
    int  m_tableEnd = 0;
    bool m_valid = false;
};
