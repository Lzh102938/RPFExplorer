#pragma once

// ============================================================================
// GXT 文本表解析器（GTA VI 的 0DRP 资源）
// ----------------------------------------------------------------------------
// 结构（与 GTA6_gxt/tools 的独立 Python 提取器完全一致，13 语种已验证）：
//   0x000000  0DRP 容器头（+0x10 处为 "0DRP"）
//   0x000060  槽位表 69,632 × 16B {u32 hash, u32 标记, u8 tag}
//   0x110060  串池 0（1MB 容量）；0x210060 串池 1；之后串池/记录表顺序不定
//   记录表    N × 16B {u32 0, u32 0, u16 class, u16 off_lo, u32 off_hi}
//             地址 = 池基址 + (((off_hi<<16)|off_lo) >> 4)
// 槽位筛选：tag==1 且 标记==0；筛出条数 == 记录表条数（13/13 验证）
// ============================================================================

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QString>

struct GxtEntry {
    uint32_t hash = 0;
    uint16_t cls = 0;
    uint32_t byteOffset = 0;
    QString  text;
};

struct GxtInfo {
    bool ok = false;
    QString error;

    int validSlots = 0;     // 槽位表筛出的哈希数
    int recordCount = 0;    // 记录表条数
    int recordOffset = -1;  // 记录表在资源内的偏移
    int decoded = 0;        // 成功解码出文本的条数
    bool tailZero = false;  // 记录表末尾字节为 0x00（结构自洽的硬证据）

    QHash<int, quint64> poolBases;   // class -> 串池基址
    QList<GxtEntry> entries;

    double decodeRatio() const {
        return recordCount > 0 ? double(decoded) / double(recordCount) : 0.0;
    }
};

class GxtParser {
public:
    // 只看容器魔数，不做完整解析（扫描时用）
    static bool looksLikeGxt(const QByteArray& blob);

    // 便宜的结构判定：0DRP 魔数 + 记录表锚点 + 有效槽位 > 100（不解码文本）
    static bool hasTextTableStructure(const QByteArray& blob);

    // 完整解析；失败时 info.ok=false 且 info.error 说明原因
    static GxtInfo parse(const QByteArray& blob);

    // idx<TAB>hash<TAB>class<TAB>text（导出用，UTF-8）
    static QString toTsv(const QList<GxtEntry>& entries);
};
