#include "EmbeddedScan.h"

#include <algorithm>
#include <cstring>
#include <QSet>
#include <zlib.h>

namespace {

inline quint32 rd32(const QByteArray& b, int o) {
    return quint32(quint8(b[o])) | (quint32(quint8(b[o + 1])) << 8)
         | (quint32(quint8(b[o + 2])) << 16) | (quint32(quint8(b[o + 3])) << 24);
}

inline quint64 rd64(const QByteArray& b, int o) {
    return quint64(rd32(b, o)) | (quint64(rd32(b, o + 4)) << 32);
}

// 逐段校验 JPEG：SOI 后必须是合法段（长度自洽），且出现过 SOF；SOS 后到 EOI
bool validJpeg(const QByteArray& d, int start, int end) {
    int p = start + 2;
    bool sof = false;
    while (p + 4 <= end) {
        if (quint8(d[p]) != 0xFF) return false;
        const int m = quint8(d[p + 1]);
        if (m == 0xD9) return false;                    // 还没见 SOF 就结束
        if (m == 0xDA) return sof;                      // SOS：熵编码数据，只要见过 SOF
        if (m == 0x01 || (m >= 0xD0 && m <= 0xD7)) { p += 2; continue; }
        const int len = (quint8(d[p + 2]) << 8) | quint8(d[p + 3]);
        if (len < 2 || p + 2 + len > end) return false;
        if (m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC) {
            if (len < 8) return false;
            const int h = (quint8(d[p + 5]) << 8) | quint8(d[p + 6]);
            const int w = (quint8(d[p + 7]) << 8) | quint8(d[p + 8]);
            if (w == 0 || h == 0) return false;
            sof = true;
        }
        p += 2 + len;
    }
    return false;
}

} // namespace

QVector<EmbeddedFile> scanEmbedded(const QByteArray& d, int maxFiles) {
    QVector<EmbeddedFile> out;
    const int n = d.size();
    if (n < 16) return out;

    // ---- SWF（FWS 未压缩 / CWS zlib 压缩） ----
    for (int i = d.indexOf(QByteArrayLiteral("FWS")); i >= 0 && i + 8 <= n;
         i = d.indexOf(QByteArrayLiteral("FWS"), i + 3)) {
        const int ver = quint8(d[i + 3]);
        const quint32 len = rd32(d, i + 4);
        if (ver < 1 || ver > 60 || len < 8 || qint64(len) > qint64(n - i)) continue;
        out.append({QStringLiteral("SWF"), QStringLiteral("swf"), i, int(len), len});
    }
    for (int i = d.indexOf(QByteArrayLiteral("CWS")); i >= 0 && i + 8 <= n;
         i = d.indexOf(QByteArrayLiteral("CWS"), i + 3)) {
        const int ver = quint8(d[i + 3]);
        if (ver < 1 || ver > 60) continue;
        z_stream zs{};
        if (inflateInit(&zs) != Z_OK) continue;
        char buf[65536];
        zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(d.constData()) + i + 8);
        zs.avail_in = uInt(n - i - 8);
        zs.next_out = reinterpret_cast<Bytef*>(buf);
        zs.avail_out = sizeof(buf);
        const int rc = inflate(&zs, Z_NO_FLUSH);
        const qint64 consumed = qint64(n - i - 8) - qint64(zs.avail_in);
        inflateEnd(&zs);
        if ((rc == Z_OK || rc == Z_STREAM_END) && consumed > 0)
            out.append({QStringLiteral("SWF"), QStringLiteral("swf"), i,
                        int(8 + consumed), rd32(d, i + 4)});
    }

    // ---- BMP ----
    for (int i = d.indexOf(QByteArrayLiteral("BM")); i >= 0 && i + 54 <= n;
         i = d.indexOf(QByteArrayLiteral("BM"), i + 2)) {
        const quint32 fsz = rd32(d, i + 2);
        const quint32 off = rd32(d, i + 10);
        const quint32 dib = rd32(d, i + 14);
        if (fsz < 26 || qint64(fsz) > qint64(n - i)) continue;
        if (off < 14 || off >= fsz) continue;
        if (dib != 12 && dib != 40 && dib != 52 && dib != 56 && dib != 108 && dib != 124)
            continue;
        if (dib >= 40) {
            const qint32 w = qint32(rd32(d, i + 18));
            const qint32 h = qint32(rd32(d, i + 22));
            if (w <= 0 || w > 65536 || h == 0 || h > 65536 || h < -65536) continue;
        }
        out.append({QStringLiteral("BMP"), QStringLiteral("bmp"), i, int(fsz), fsz});
        i += int(fsz) - 2;
    }

    // ---- JPEG（扫到 EOI） ----
    const QByteArray soi = QByteArrayLiteral("\xFF\xD8\xFF");
    const QByteArray eoi = QByteArrayLiteral("\xFF\xD9");
    for (int i = d.indexOf(soi); i >= 0; i = d.indexOf(soi, i + 2)) {
        const int e = d.indexOf(eoi, i + 3);
        if (e < 0) break;
        const int size = e + 2 - i;
        if (size < 64 || size > (32 << 20)) continue;
        if (!validJpeg(d, i, e + 2)) continue;   // 段结构不成立 → 压缩数据里的偶然标记
        out.append({QStringLiteral("JPEG"), QStringLiteral("jpg"), i, size, quint32(size)});
        i = e;
    }

    // ---- RIFF ----
    for (int i = d.indexOf(QByteArrayLiteral("RIFF")); i >= 0 && i + 12 <= n;
         i = d.indexOf(QByteArrayLiteral("RIFF"), i + 4)) {
        const quint32 sz = rd32(d, i + 4);
        if (sz < 4 || qint64(sz) + 8 > qint64(n - i)) continue;
        out.append({QStringLiteral("RIFF"), QStringLiteral("riff"), i, int(sz) + 8, sz});
        i += int(sz) + 8 - 4;
    }

    // ---- DDS ----
    for (int i = d.indexOf(QByteArrayLiteral("DDS ")); i >= 0 && i + 128 <= n;
         i = d.indexOf(QByteArrayLiteral("DDS "), i + 4)) {
        if (rd32(d, i + 4) != 124) continue;
        const quint32 h = rd32(d, i + 12);
        const quint32 w = rd32(d, i + 16);
        if (!w || !h || w > 65536 || h > 65536) continue;
        out.append({QStringLiteral("DDS"), QStringLiteral("dds"), i, n - i, quint32(n - i)});
    }

    // 按偏移排序，丢弃落在已接受文件内部的结果（BMP 像素里常有假 JPEG/SWF 头）
    std::sort(out.begin(), out.end(), [](const EmbeddedFile& a, const EmbeddedFile& b) {
        return a.offset < b.offset;
    });
    QVector<EmbeddedFile> keep;
    for (const EmbeddedFile& e : out) {
        bool inside = false;
        for (const EmbeddedFile& k : keep) {
            if (e.offset >= k.offset && e.offset < k.offset + k.size) {
                inside = true;
                break;
            }
        }
        if (!inside) keep.append(e);
        if (keep.size() >= maxFiles) break;
    }
    return keep;
}

QStringList rbfStrings(const QByteArray& d, int maxStrings) {
    QStringList out;
    for (int i = 0; i + 2 <= d.size() && out.size() < maxStrings; ++i) {
        const int len = quint8(d[i]) | (quint8(d[i + 1]) << 8);
        if (len < 3 || len > 120 || i + 2 + len > d.size()) continue;
        const quint8 c0 = quint8(d[i + 2]);
        if (!((c0 >= 0x20 && c0 < 0x7F) || c0 >= 0xC2)) continue;
        const QByteArray s = d.mid(i + 2, len);
        bool ok = true;
        int alnum = 0;
        for (char c : s) {
            const quint8 u = quint8(c);
            if (u < 0x20 || u == 0x7F) { ok = false; break; }
            if ((u >= '0' && u <= '9') || (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z'))
                ++alnum;
        }
        if (!ok || alnum < 2) continue;
        const QString t = QString::fromUtf8(s);
        if (t.isEmpty() || t.toUtf8() != s) continue;
        out.append(t);
        i += 1 + len;
    }
    return out;
}

// PSIN 块链：{char tag[4]; u32 BE totalSize(含 8 字节头)}，兄弟块依次排列
QVector<PsinChunk> psinChunks(const QByteArray& d) {
    static const char* kTags[] = {"LSCH", "LENM", "LSNS", "LGID", "LRSC", "CHKS"};
    auto isTag = [](const QByteArray& t) {
        for (const char* s : kTags)
            if (t == QByteArray(s, 4)) return true;
        return false;
    };
    auto be32 = [](const QByteArray& b, int o) {
        return (quint32(quint8(b[o])) << 24) | (quint32(quint8(b[o + 1])) << 16)
             | (quint32(quint8(b[o + 2])) << 8) | quint32(quint8(b[o + 3]));
    };
    QVector<PsinChunk> out;
    const int n = d.size();
    for (int start = 0x08; start + 8 <= n && start < 0x4000; ++start) {
        if (!isTag(d.mid(start, 4))) continue;
        QVector<PsinChunk> seq;
        int pos = start;
        while (pos + 8 <= n) {
            const QByteArray tag = d.mid(pos, 4);
            if (!isTag(tag)) break;
            const quint32 size = be32(d, pos + 4);
            if (size < 8 || quint64(pos) + size > quint64(n)) break;
            seq.append({QString::fromLatin1(tag), pos, int(size)});
            pos += int(size);
            if (seq.size() > 64) break;
        }
        if (pos == n || (seq.size() >= 3 && n - pos <= 16)) {
            return seq;
        }
    }
    return out;
}

QVector<PsinSchemaRecord> psinSchema(const QByteArray& d) {
    QVector<PsinSchemaRecord> out;
    for (int o = 0; o + 32 <= d.size(); o += 32) {
        PsinSchemaRecord r;
        r.hash = rd64(d, o);
        r.flags = rd32(d, o + 8);
        r.u12 = rd32(d, o + 12);
        r.data = rd64(d, o + 16);
        r.off = rd32(d, o + 24);
        r.aux = rd32(d, o + 28);
        out.append(r);
    }
    return out;
}

static QStringList textRuns(const QByteArray& data, int minLen, int maxRuns) {
    QStringList out;
    int start = -1;
    for (int i = 0; i <= data.size(); ++i) {
        const quint8 c = i < data.size() ? quint8(data[i]) : 0;
        const bool ok = (c >= 0x20 && c < 0x7F) || c == '\n' || c == '\r'
                     || c == '\t' || c >= 0xC2;
        if (ok) {
            if (start < 0) start = i;
        } else {
            if (start >= 0 && i - start >= minLen) {
                const QByteArray raw = data.mid(start, i - start);
                const QString t = QString::fromUtf8(raw).trimmed();
                if (!t.isEmpty() && t.toUtf8() == raw.trimmed()) {
                    int letters = 0;
                    for (const QChar ch : t)
                        if (ch.isLetter()) ++letters;
                    if (letters >= 3) out << t;
                }
                if (out.size() >= maxRuns) return out;
            }
            start = -1;
        }
    }
    return out;
}

QVector<DrpItem> drpItems(const QByteArray& d) {
    QVector<DrpItem> out;
    if (d.size() < 0x64) return out;
    const quint32 s = rd32(d, 0x38);
    const quint32 e = rd32(d, 0x40);
    if (s < 0x50000000u || e < 0x50000000u) return out;
    const int lo = int(s - 0x50000000u);
    const int hi = int(e - 0x50000000u);
    if (lo < 0x60 || hi > d.size() || lo >= hi) return out;
    for (int o = lo; o + 16 <= hi; o += 16) {
        const quint64 v = rd64(d, o);
        const quint64 p = rd64(d, o + 8);
        if (p < 0x50000000ull) break;
        const quint64 off = p - 0x50000000ull;
        const quint32 size = quint32(v >> 32);
        if (size == 0 || off >= quint64(d.size()) || quint64(size) > quint64(d.size()) - off)
            break;
        out.append({quint32(v), size, quint32(off)});
    }
    return out;
}

QString drpSectionName(quint32 id) {
    switch (id) {
        case 0x00000010u: return QStringLiteral("字符串池");
        case 0x00000101u: return QStringLiteral("数据块");
        case 0x99331089u: return QStringLiteral("索引头");
        case 0xa8478889u: return QStringLiteral("记录表");
        case 0xc90d1c34u: return QStringLiteral("头");
        case 0xfc3dbc38u: return QStringLiteral("数据块");
        case 0x956a9df5u: return QStringLiteral("辅助表");
        case 0x10075946u: return QStringLiteral("辅助数据");
        case 0xd7e9c53bu: return QStringLiteral("数值块");
        case 0x8731ec16u: return QStringLiteral("记录");
        case 0xac393bccu: return QStringLiteral("主数据");
    }
    return QStringLiteral("段 0x%1").arg(id, 8, 16, QChar('0'));
}

QString drpContainerKind(const QVector<DrpItem>& items) {
    QSet<quint32> ids;
    for (const DrpItem& it : items) ids.insert(it.id);
    const bool hasText = ids.contains(0x10u);
    if (hasText && ids.contains(0x101u) && ids.contains(0x99331089u)
        && ids.contains(0xa8478889u)) {
        return ids.size() == 4
                   ? QStringLiteral("对白 / UI 文本包（4 段）")
                   : QStringLiteral("扩展文本包（%1 段，含 1 MB 大块）").arg(ids.size());
    }
    if (ids.contains(0xc90d1c34u) && ids.contains(0xfc3dbc38u))
        return QStringLiteral("资源包（2 段）");
    if (ids.contains(0x8731ec16u) && ids.contains(0xd7e9c53bu))
        return QStringLiteral("小资源包（%1 段）").arg(ids.size());
    return QStringLiteral("通用资源容器（%1 段）").arg(ids.size());
}

QByteArray drpTextPool(const QByteArray& d, const QVector<DrpItem>& items) {
    for (const DrpItem& it : items)
        if (it.id == 0x10u) return d.mid(it.offset, it.size);
    return {};
}

QStringList drpPoolStrings(const QByteArray& pool, int maxStrings) {
    QStringList out;
    int start = 0;
    for (int i = 0; i <= pool.size(); ++i) {
        if (i < pool.size() && pool.at(i) != '\0') continue;
        if (i > start) {
            out << QString::fromUtf8(pool.constData() + start, i - start);
            if (maxStrings > 0 && out.size() >= maxStrings) return out;
        }
        start = i + 1;
    }
    return out;
}

QString drpTextLanguage(const QStringList& strings) {
    qint64 latin = 0, cjk = 0, kana = 0, hang = 0, cyr = 0;
    for (const QString& s : strings) {
        for (const QChar ch : s) {
            const ushort u = ch.unicode();
            if (u >= 0x4E00 && u <= 0x9FFF) ++cjk;
            else if (u >= 0x3040 && u <= 0x30FF) ++kana;
            else if (u >= 0xAC00 && u <= 0xD7AF) ++hang;
            else if (u >= 0x0400 && u <= 0x04FF) ++cyr;
            else if ((u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z')) ++latin;
        }
    }
    if (kana > 50) return QStringLiteral("日文");
    if (hang > 50) return QStringLiteral("韩文");
    if (cjk > 50) return QStringLiteral("中文");
    if (cyr > 50) return QStringLiteral("俄文");
    if (latin > 50) return QStringLiteral("拉丁语系（英/法/德/西/意/葡/波等）");
    return QStringLiteral("未知（字符串过少）");
}

QStringList embeddedAssetNames(const QByteArray& d, int maxNames) {
    static const char* kExts[] = {
        "ydr", "yft", "ytd", "ybn", "ycd", "ypt",
        "yld", "ymap", "ytyp", "ycs", "ywt", "yvr",
    };
    QStringList out;
    QSet<QString> seen;
    const int n = d.size();
    const uchar* p = reinterpret_cast<const uchar*>(d.constData());
    auto isAlpha = [](uchar c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    };
    auto isNameChar = [&](uchar c) {
        return isAlpha(c) || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '#';
    };

    int i = 0;
    while (i < n && (maxNames <= 0 || out.size() < maxNames)) {
        if (!isAlpha(p[i])) { ++i; continue; }
        const int start = i;
        int lastDot = -1;
        bool doubleDot = false;
        bool prevDot = false;
        while (i < n && isNameChar(p[i])) {
            const uchar c = p[i];
            if (c == '.') {
                if (prevDot) doubleDot = true;
                lastDot = i;
                prevDot = true;
            } else {
                prevDot = false;
            }
            ++i;
        }
        const int len = i - start;
        if (len < 5 || len > 96 || doubleDot || lastDot <= start) continue;

        const int suffixLen = i - lastDot - 1;
        const uchar* suffix = p + lastDot + 1;
        bool okExt = (suffixLen == 3 && suffix[0] == '#'
                      && isAlpha(suffix[1]) && isAlpha(suffix[2]));
        for (int k = 0; !okExt && k < int(sizeof(kExts) / sizeof(kExts[0])); ++k) {
            if (int(std::strlen(kExts[k])) == suffixLen
                && std::memcmp(suffix, kExts[k], suffixLen) == 0)
                okExt = true;
        }
        if (!okExt) continue;

        const QString name = QString::fromLatin1(d.constData() + start, len);
        if (!seen.contains(name)) {
            seen.insert(name);
            out << name;
        }
    }
    return out;
}

QString languageKeyFromPath(const QString& relPath) {
    const int p = relPath.indexOf(QLatin1String("lang/"));
    if (p < 0) return {};
    QString seg = relPath.mid(p + 5);
    const int slash = seg.indexOf(QLatin1Char('/'));
    if (slash >= 0) seg = seg.left(slash);
    if (seg.endsWith(QLatin1String(".rpf"))) seg.chop(4);
    if (seg.endsWith(QLatin1String("_final"))) seg.chop(6);

    static const QSet<QString> kKnown = {
        QStringLiteral("american"), QStringLiteral("brazilian"),
        QStringLiteral("chinesesimp"), QStringLiteral("chinesetrad"),
        QStringLiteral("french"), QStringLiteral("german"),
        QStringLiteral("italian"), QStringLiteral("japanese"),
        QStringLiteral("korean"), QStringLiteral("mexican"),
        QStringLiteral("polish"), QStringLiteral("russian"),
        QStringLiteral("spanish"),
    };
    return kKnown.contains(seg) ? seg : QString();
}

QString languageDisplayName(const QString& key) {
    static const QHash<QString, QString> kNames = {
        {QStringLiteral("american"),    QStringLiteral("英文")},
        {QStringLiteral("brazilian"),   QStringLiteral("葡萄牙文（巴西）")},
        {QStringLiteral("chinesesimp"), QStringLiteral("简体中文")},
        {QStringLiteral("chinesetrad"), QStringLiteral("繁体中文")},
        {QStringLiteral("french"),      QStringLiteral("法文")},
        {QStringLiteral("german"),      QStringLiteral("德文")},
        {QStringLiteral("italian"),     QStringLiteral("意大利文")},
        {QStringLiteral("japanese"),    QStringLiteral("日文")},
        {QStringLiteral("korean"),      QStringLiteral("韩文")},
        {QStringLiteral("mexican"),     QStringLiteral("西班牙文（墨西哥）")},
        {QStringLiteral("polish"),      QStringLiteral("波兰文")},
        {QStringLiteral("russian"),     QStringLiteral("俄文")},
        {QStringLiteral("spanish"),     QStringLiteral("西班牙文")},
    };
    return kNames.value(key, key);
}

QString psinReport(const QByteArray& d) {
    QString s = QStringLiteral("PSIN 结构化报告\n");
    const QVector<PsinChunk> chunks = psinChunks(d);
    if (!chunks.isEmpty())
        s += QStringLiteral("块链: %1 块\n").arg(chunks.size());

    QByteArray lsch, lsns;
    for (const PsinChunk& c : chunks) {
        s += QStringLiteral("  %1 @0x%2 大小=%3 负载=%4\n")
                 .arg(c.tag).arg(c.offset, 0, 16).arg(c.size).arg(c.size - 8);
        if (c.tag == QLatin1String("LSCH"))
            lsch = d.mid(c.offset + 8, c.size - 8);
        else if (c.tag == QLatin1String("LSNS"))
            lsns = d.mid(c.offset + 8, c.size - 8);
    }

    if (chunks.isEmpty()) {
        s += QStringLiteral("块链: 未找到（文本 / 页索引变体）\n块表（16 字节/条）:\n");
        int o = 0x08, n = 0;
        while (o + 16 <= d.size() && n < 64) {
            const quint32 size = rd32(d, o + 4);
            if (rd64(d, o + 8) != 0xAAAAAAAAAAAAAAAAull || size == 0
                || quint64(size) > quint64(d.size()))
                break;
            s += QStringLiteral("  #%1 tag=0x%2 size=%3\n")
                     .arg(n).arg(rd32(d, o), 0, 16).arg(size);
            ++n;
            o += 16;
        }
        if (n == 0) s += QStringLiteral("  （无）\n");
        const QStringList all = textRuns(d, 8, 5000);   // textRuns 定义在本文件上方
        if (!all.isEmpty()) {
            s += QStringLiteral("文本片段: %1 条\n").arg(all.size());
            for (const QString& t : all) s += QStringLiteral("  %1\n").arg(t);
        }
        return s;
    }

    if (!lsch.isEmpty()) {
        const QVector<PsinSchemaRecord> recs = psinSchema(lsch);
        int fields = 0;
        for (const PsinSchemaRecord& r : recs)
            if (r.data == 0xAAAAAAAAAAAAAAAAull && (r.flags & 0x200)) ++fields;
        s += QStringLiteral("字段记录: %1 条；其它记录: %2 条（LSCH 负载 %3 字节）\n")
                 .arg(fields).arg(recs.size() - fields).arg(lsch.size());
        s += QStringLiteral("字段记录（32 字节/条；hash 为 64 位字段名哈希，不可逆）:\n");
        int printed = 0;
        for (const PsinSchemaRecord& r : recs) {
            if (!(r.data == 0xAAAAAAAAAAAAAAAAull && (r.flags & 0x200))) continue;
            s += QStringLiteral("  #%1 hash=%2 flags=0x%3 off=0x%4 aux=0x%5\n")
                     .arg(printed, 3)
                     .arg(r.hash, 16, 16, QChar('0'))
                     .arg(r.flags, 3, 16, QChar('0'))
                     .arg(r.off, 0, 16)
                     .arg(r.aux, 0, 16);
            ++printed;
        }
        if (recs.size() > fields) {
            s += QStringLiteral("其它记录（未定型，原样 32 字节）:\n");
            int shown = 0;
            for (const PsinSchemaRecord& r : recs) {
                if (r.data == 0xAAAAAAAAAAAAAAAAull && (r.flags & 0x200)) continue;
                if (++shown > 64) { s += QStringLiteral("  …\n"); break; }
                s += QStringLiteral("  %1 %2 %3 %4\n")
                         .arg(r.hash, 16, 16, QChar('0'))
                         .arg(r.flags, 8, 16, QChar('0'))
                         .arg(r.off, 8, 16, QChar('0'))
                         .arg(r.data, 16, 16, QChar('0'));
            }
        }
        if (lsch.size() % 32)
            s += QStringLiteral("  （尾部 %1 字节未按 32 字节对齐）\n").arg(lsch.size() % 32);
    } else {
        s += QStringLiteral("模式记录: 未找到 LSCH 块\n");
    }

    if (!lsns.isEmpty()) {
        s += QStringLiteral("取值块: %1 字节").arg(lsns.size());
        if (lsns.size() >= 12) {
            s += QStringLiteral("（头: count=%1 flags=0x%2 size=%3）")
                     .arg(rd32(lsns, 0)).arg(rd32(lsns, 4), 0, 16).arg(rd32(lsns, 8));
        }
        s += QLatin1Char('\n');

        const QStringList runs = textRuns(lsns, 8, 5000);
        if (!runs.isEmpty()) {
            s += QStringLiteral("文本片段: %1 条\n").arg(runs.size());
            for (const QString& t : runs) s += QStringLiteral("  %1\n").arg(t);
        }
    }
    return s;
}
