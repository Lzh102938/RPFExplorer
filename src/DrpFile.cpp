#include "DrpFile.h"

#include <cstring>

namespace {

inline quint32 rd32(const QByteArray& b, int o) {
    return quint32(quint8(b[o])) | (quint32(quint8(b[o + 1])) << 8)
         | (quint32(quint8(b[o + 2])) << 16) | (quint32(quint8(b[o + 3])) << 24);
}
inline void wr32(QByteArray& b, int o, quint32 v) {
    b[o] = char(v & 0xFF); b[o + 1] = char((v >> 8) & 0xFF);
    b[o + 2] = char((v >> 16) & 0xFF); b[o + 3] = char((v >> 24) & 0xFF);
}
inline void wr64(QByteArray& b, int o, quint64 v) {
    for (int k = 0; k < 8; ++k) b[o + k] = char((v >> (8 * k)) & 0xFF);
}

} // namespace

quint32 DrpFile::field(int off) const {
    if (off < 0 || off + 4 > m_raw.size()) return 0;
    return rd32(m_raw, off);
}

bool DrpFile::parse(const QByteArray& data) {
    m_raw = data;
    m_items.clear();
    m_tableOff = m_tableEnd = 0;
    m_valid = false;
    if (data.size() < 0x64 || data.mid(0x10, 4) != QByteArrayLiteral("0DRP"))
        return false;
    const quint32 s = rd32(data, 0x38);
    const quint32 e = rd32(data, 0x40);
    if (s < 0x50000000u || e < 0x50000000u) return false;
    m_tableOff = int(s - 0x50000000u);
    m_tableEnd = int(e - 0x50000000u);
    if (m_tableOff < 0x60 || m_tableEnd > data.size() || m_tableOff >= m_tableEnd)
        return false;
    m_items = drpItems(data);
    m_valid = !m_items.isEmpty();
    return m_valid;
}

QByteArray DrpFile::serialize() const {
    QByteArray out = m_raw;                       // 未建模区域原样保留
    if (out.size() < 0x60) return out;

    // 1) 头部指针由结构重写（+0x38 / +0x40）
    wr32(out, 0x38, 0x50000000u | quint32(m_tableOff));
    wr32(out, 0x40, 0x50000000u | quint32(m_tableEnd));

    // 2) 表项由结构重写：{u64 size<<32|段ID, u64 0x50000000|offset}
    for (int i = 0; i < m_items.size(); ++i) {
        const int o = m_tableOff + i * 16;
        if (o + 16 > out.size()) break;
        wr64(out, o, (quint64(m_items[i].size) << 32) | m_items[i].id);
        wr64(out, o + 8, 0x50000000ull | m_items[i].offset);
    }

    // 3) 子资源数据按 offset/size 从原字节重新落位（写回路径与解析路径对称）
    for (const DrpItem& it : m_items) {
        if (it.offset + it.size > quint32(m_raw.size())) continue;
        std::memcpy(out.data() + it.offset, m_raw.constData() + it.offset, it.size);
    }
    return out;
}

bool DrpFile::roundTripOk() const {
    if (!m_valid) return false;
    return serialize() == m_raw;
}
