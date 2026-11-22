#include "GxtParser.h"

#include <QStringConverter>

#include <algorithm>

namespace {

constexpr int SLOT_BASE  = 0x60;
constexpr int SLOT_BYTES = 0x110000;                 // 69,632 × 16
constexpr int POOL_A     = SLOT_BASE + SLOT_BYTES;   // 0x110060
constexpr int POOL_UNIT  = 1 << 20;                  // 单个串池容量上限 1 MB
constexpr int MAX_POOLS  = 12;
constexpr int CLASS_MIN  = 1;
constexpr int CLASS_MAX  = 16;

inline uint16_t rd16(const char* p) {
    return uint16_t(uint8_t(p[0])) | uint16_t(uint16_t(uint8_t(p[1])) << 8);
}
inline uint32_t rd32(const char* p) {
    return uint32_t(uint8_t(p[0]))
         | (uint32_t(uint8_t(p[1])) << 8)
         | (uint32_t(uint8_t(p[2])) << 16)
         | (uint32_t(uint8_t(p[3])) << 24);
}

// 从 pos 读一个 NUL 结尾的 UTF-8 串；非法 UTF-8 / 越界 / 无 NUL 返回 false
bool decodeAt(const QByteArray& b, qint64 pos, QString* out) {
    if (pos <= 0 || pos >= b.size()) return false;
    const int start = int(pos);
    const int limit = int(qMin<qint64>(b.size(), pos + 65536));
    const int nul = b.indexOf('\0', start);
    if (nul < 0 || nul >= limit) return false;
    const QByteArray bytes = b.mid(start, nul - start);
    QStringDecoder dec(QStringDecoder::Utf8);
    const QString s = dec.decode(bytes);
    if (dec.hasError()) return false;
    if (out) *out = s;
    return true;
}

// 槽位表 -> 稠密哈希列表：tag(+8)==1 且 标记(+4)==0
QList<uint32_t> readHashes(const QByteArray& b) {
    QList<uint32_t> out;
    const char* base = b.constData() + SLOT_BASE;
    const int slotCount = SLOT_BYTES / 16;
    for (int k = 0; k < slotCount; ++k) {
        const char* p = base + k * 16;
        if (uint8_t(p[8]) == 1 && rd32(p + 4) == 0)
            out.append(rd32(p));
    }
    return out;
}

// 记录表锚点：首条记录恒为 class=4 / 偏移 0，随后 200 条 class 合法且偏移不减
int findRecords(const QByteArray& b) {
    QByteArray pat(26, '\0');
    pat[8] = char(0x04);    // 第一条记录 class=4
    pat[24] = char(0x04);   // 第二条记录 class=4
    int pos = POOL_A;
    while (true) {
        const int i = b.indexOf(pat, pos);
        if (i < 0) return -1;
        pos = i + 1;
        int ok = 0;
        uint32_t prev = 0;
        bool havePrev = false;
        for (int k = 0; k < 200; ++k) {
            const int p = i + k * 16;
            if (p + 16 > b.size()) break;
            const uint16_t cls = rd16(b.constData() + p + 8);
            const uint32_t raw = rd32(b.constData() + p + 12) * 65536u
                               + rd16(b.constData() + p + 10);
            if (cls >= CLASS_MIN && cls <= CLASS_MAX && (!havePrev || raw >= prev)) {
                ++ok;
                prev = raw;
                havePrev = true;
            }
        }
        if (ok >= 190) return i;
    }
}

struct Rec {
    uint16_t cls = 0;
    uint32_t off = 0;     // 已 >>4 的字节偏移
};

QList<Rec> readRecords(const QByteArray& b, int rec, int count) {
    QList<Rec> out;
    out.reserve(count);
    const char* base = b.constData();
    for (int k = 0; k < count; ++k) {
        const char* p = base + rec + k * 16;
        Rec r;
        r.cls = rd16(p + 8);
        r.off = (rd32(p + 12) * 65536u + rd16(p + 10)) >> 4;
        out.append(r);
    }
    return out;
}

// 串池基址投票：候选 = 0x110060 + q*1MB，外加记录表末尾的尾部串池
QHash<int, quint64> resolvePools(const QByteArray& b, int rec, int count,
                                 const QList<Rec>& recs) {
    QList<qint64> cands;
    for (int q = 0; q < MAX_POOLS; ++q)
        cands.append(qint64(POOL_A) + qint64(q) * POOL_UNIT);
    cands.append(qint64(rec) + qint64(count) * 16);

    QList<qint64> valid;
    for (qint64 c : cands)
        if (c < b.size()) valid.append(c);

    QList<int> classes;
    for (const Rec& r : recs)
        if (!classes.contains(r.cls)) classes.append(r.cls);
    std::sort(classes.begin(), classes.end());

    QHash<int, quint64> bases;
    for (int cls : classes) {
        QList<uint32_t> offs;
        for (const Rec& r : recs)
            if (r.cls == cls) offs.append(r.off);
        if (offs.isEmpty()) continue;

        const int step = std::max(1, int(offs.size() / 2000));
        int bestHit = -1;
        qint64 bestBase = valid.isEmpty() ? 0 : valid.first();
        for (qint64 base : valid) {
            int hit = 0;
            for (int i = 0; i < offs.size(); i += step) {
                const qint64 pos = base + qint64(offs[i]);
                if (pos <= 0 || pos >= b.size()) continue;
                if (b[int(pos) - 1] != 0) continue;          // 必须落在串首
                if (!decodeAt(b, pos, nullptr)) continue;
                ++hit;
            }
            if (hit > bestHit) {
                bestHit = hit;
                bestBase = base;
            }
        }
        bases.insert(cls, quint64(bestBase));
    }
    return bases;
}

} // namespace

bool GxtParser::looksLikeGxt(const QByteArray& blob) {
    return blob.size() > 0x14 && blob.mid(0x10, 4) == QByteArrayLiteral("0DRP");
}

bool GxtParser::hasTextTableStructure(const QByteArray& blob) {
    if (!looksLikeGxt(blob) || blob.size() < POOL_A + 64) return false;
    if (findRecords(blob) < 0) return false;
    int n = 0;
    const char* base = blob.constData() + SLOT_BASE;
    for (int k = 0; k < SLOT_BYTES / 16 && n <= 100; ++k) {
        const char* p = base + k * 16;
        if (uint8_t(p[8]) == 1 && rd32(p + 4) == 0) ++n;
    }
    return n > 100;
}

GxtInfo GxtParser::parse(const QByteArray& blob) {
    GxtInfo inf;
    if (!looksLikeGxt(blob)) {
        inf.error = QStringLiteral("不是 0DRP 容器");
        return inf;
    }
    if (blob.size() < POOL_A + 64) {
        inf.error = QStringLiteral("资源小于 0DRP 槽位区（%1 字节）").arg(blob.size());
        return inf;
    }

    const QList<uint32_t> hashes = readHashes(blob);
    const int rec = findRecords(blob);
    if (rec < 0) {
        inf.error = QStringLiteral("记录表定位失败：这是 0DRP 二进制资源，不是文本表");
        return inf;
    }
    const int count = qMin(hashes.size(), (blob.size() - rec) / 16);
    if (count <= 0) {
        inf.error = QStringLiteral("记录表为空");
        return inf;
    }

    const QList<Rec> recs = readRecords(blob, rec, count);
    inf.poolBases   = resolvePools(blob, rec, count, recs);
    inf.validSlots  = hashes.size();
    inf.recordCount = count;
    inf.recordOffset = rec;
    inf.entries.reserve(count);

    for (int k = 0; k < count; ++k) {
        GxtEntry e;
        e.hash = hashes[k];
        e.cls = recs[k].cls;
        e.byteOffset = recs[k].off;
        QString txt;
        const auto it = inf.poolBases.constFind(int(recs[k].cls));
        if (it != inf.poolBases.constEnd() &&
            decodeAt(blob, qint64(it.value()) + recs[k].off, &txt)) {
            e.text = txt;
            if (!txt.isEmpty()) ++inf.decoded;
        }
        inf.entries.append(e);
    }

    const qint64 tail = qint64(rec) + qint64(count) * 16;
    inf.tailZero = (tail < blob.size() && blob[int(tail)] == 0);
    inf.ok = (inf.validSlots == inf.recordCount) && (inf.decodeRatio() >= 0.5);
    if (!inf.ok)
        inf.error = QStringLiteral("槽位/记录数量不匹配或文本解码率过低（不是文本表）");
    return inf;
}

QString GxtParser::toTsv(const QList<GxtEntry>& entries) {
    QString out;
    out.reserve(entries.size() * 48);
    out += QStringLiteral("idx\thash\tclass\ttext\n");
    int idx = 0;
    for (const GxtEntry& e : entries) {
        QString text = e.text;
        text.replace(QLatin1Char('\t'), QLatin1Char(' '));
        text.replace(QLatin1Char('\n'), QChar(0x00B7));
        text.replace(QLatin1Char('\r'), QLatin1Char(' '));
        const QString hashStr = QStringLiteral("%1")
                                    .arg(e.hash, 8, 16, QChar('0')).toUpper();
        out += QStringLiteral("%1\t%2\t%3\t%4\n")
                   .arg(idx++)
                   .arg(hashStr)
                   .arg(e.cls)
                   .arg(text);
    }
    return out;
}
