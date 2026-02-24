#include "meow_crypto.h"

#include <string>
#include <vector>
#include <cstdint>

namespace meowcrypto {

namespace {

const std::string kDefaultKey = "12#$";

// 16个GBK编码的中文字符 + "~"修饰符 = 32符号（5bit）
// GBK每字符2字节，比UTF-8的3字节更紧凑
// 编码方式：8符号 = 40bit = 5字节数据
// 输出：8×(2~3)字节 = 16~24字节
// 密度：5/16 ≈ 31%（比UTF-8方案提升约50%）
const char kCharsGBK[16][3] = {
    "\xC3\xA8",  // 喵 GBK: C3A8
    "\xCE\xD8",  // 呜 GBK: CED8
    "\xDF\xE4",  // 咪 GBK: DFE4
    "\xE0\xBA",  // 嗷 GBK: E0BA
    "\xBA\xF4",  // 呼 GBK: BAF4
    "\xE0\xBD",  // 噜 GBK: E0BD
    "\xB9\xFE",  // 哈 GBK: B9FE
    "\xCB\xBB",  // 嘶 GBK: CBBB
    "\xE0\xC5",  // 嗯 GBK: E0C5
    "\xBA\xDF",  // 哼 GBK: BADF
    "\xE0\xE9",  // 唔 GBK: E0E9
    "\xD8\xB4",  // 啾 GBK: D8B4
    "\xE0\xA4",  // 嘤 GBK: E0A4
    "\xDF\xC0",  // 咕 GBK: DFC0
    "\xD3\xB4",  // 呦 GBK: D3B4
    "\xBA\xF0",  // 吼 GBK: BAF0
};

// UTF-8编码（用于输出显示）
const char kCharsUTF8[16][4] = {
    "\xE5\x96\xB5",  // 喵
    "\xE5\x91\x9C",  // 呜
    "\xE5\x92\xAA",  // 咪
    "\xE5\x97\xB7",  // 嗷
    "\xE5\x91\xBC",  // 呼
    "\xE5\x99\x9C",  // 噜
    "\xE5\x93\x88",  // 哈
    "\xE5\x98\xB6",  // 嘶
    "\xE5\x97\xAF",  // 嗯
    "\xE5\x93\xBC",  // 哼
    "\xE5\x94\x94",  // 唔
    "\xE5\x95\xBE",  // 啾
    "\xE5\x98\xA4",  // 嘤
    "\xE5\x92\x95",  // 咕
    "\xE5\x91\xA6",  // 呦
    "\xE5\x90\xBC",  // 吼
};

const char kTilde = '~';         // 修饰符，表示+16
const size_t kGBKCharSize = 2;   // GBK每字符2字节
const size_t kUTF8CharSize = 3;  // UTF-8每字符3字节

// GBK编码转UTF-8（用于输出）
std::string gbk_to_utf8(const std::string& gbk) {
  std::string out;
  size_t i = 0;
  while (i < gbk.size()) {
    if (gbk[i] == kTilde) {
      out += kTilde;
      ++i;
      continue;
    }
    // 尝试匹配GBK字符
    bool matched = false;
    if (i + kGBKCharSize <= gbk.size()) {
      for (int d = 0; d < 16; ++d) {
        if (gbk.compare(i, kGBKCharSize, kCharsGBK[d], kGBKCharSize) == 0) {
          out.append(kCharsUTF8[d], kUTF8CharSize);
          i += kGBKCharSize;
          matched = true;
          break;
        }
      }
    }
    if (!matched) {
      out += gbk[i++];  // 保持原样
    }
  }
  return out;
}

// UTF-8编码转GBK（用于解码输入）
std::string utf8_to_gbk(const std::string& utf8) {
  std::string out;
  size_t i = 0;
  while (i < utf8.size()) {
    if (utf8[i] == kTilde) {
      out += kTilde;
      ++i;
      continue;
    }
    // 尝试匹配UTF-8字符
    bool matched = false;
    if (i + kUTF8CharSize <= utf8.size()) {
      for (int d = 0; d < 16; ++d) {
        if (utf8.compare(i, kUTF8CharSize, kCharsUTF8[d], kUTF8CharSize) == 0) {
          out.append(kCharsGBK[d], kGBKCharSize);
          i += kUTF8CharSize;
          matched = true;
          break;
        }
      }
    }
    if (!matched) {
      out += utf8[i++];  // 保持原样
    }
  }
  return out;
}

// ============ 简单LZ压缩 ============
// 格式：
// - 字面量：0xxxxxxx (7bit长度) + 数据
// - 回引：1xxxxxxx yyyyyyyy (偏移=x, 长度=y+3)
// 最大回看窗口127字节，最大匹配长度258

std::string lz_compress(const std::string& input) {
  std::string out;
  size_t i = 0;
  size_t n = input.size();

  while (i < n) {
    // 寻找最长匹配
    size_t best_offset = 0;
    size_t best_len = 0;
    size_t window_start = (i > 127) ? (i - 127) : 0;

    for (size_t j = window_start; j < i; ++j) {
      size_t len = 0;
      while (i + len < n && len < 258 && input[j + len] == input[i + len]) {
        ++len;
      }
      if (len >= 3 && len > best_len) {
        best_len = len;
        best_offset = i - j;
      }
    }

    if (best_len >= 3) {
      // 输出回引: 1xxxxxxx yyyyyyyy
      out.push_back(static_cast<char>(0x80 | (best_offset & 0x7F)));
      out.push_back(static_cast<char>((best_len - 3) & 0xFF));
      i += best_len;
    } else {
      // 收集字面量（最多127字节）
      size_t lit_start = i;
      size_t lit_len = 0;
      while (i < n && lit_len < 127) {
        // 检查是否有匹配
        bool has_match = false;
        size_t ws = (i > 127) ? (i - 127) : 0;
        for (size_t j = ws; j < i; ++j) {
          size_t len = 0;
          while (i + len < n && len < 258 && input[j + len] == input[i + len]) {
            ++len;
          }
          if (len >= 3) {
            has_match = true;
            break;
          }
        }
        if (has_match) break;
        ++i;
        ++lit_len;
      }
      // 输出字面量: 0xxxxxxx + 数据
      out.push_back(static_cast<char>(lit_len & 0x7F));
      out.append(input, lit_start, lit_len);
    }
  }
  return out;
}

std::string lz_decompress(const std::string& input, bool& ok) {
  std::string out;
  size_t i = 0;
  size_t n = input.size();
  ok = true;

  while (i < n) {
    unsigned char tag = static_cast<unsigned char>(input[i++]);
    if (tag & 0x80) {
      // 回引
      if (i >= n) {
        ok = false;
        return "";
      }
      size_t offset = tag & 0x7F;
      size_t len = static_cast<unsigned char>(input[i++]) + 3;
      if (offset == 0 || offset > out.size()) {
        ok = false;
        return "";
      }
      size_t src = out.size() - offset;
      for (size_t j = 0; j < len; ++j) {
        out.push_back(out[src + j]);
      }
    } else {
      // 字面量
      size_t len = tag;
      if (i + len > n) {
        ok = false;
        return "";
      }
      out.append(input, i, len);
      i += len;
    }
  }
  return out;
}

// ============ 核心加密函数 ============

uint32_t fnv1a_32(const std::string& s) {
  uint32_t hash = 2166136261u;
  for (unsigned char c : s) {
    hash ^= c;
    hash *= 16777619u;
  }
  return hash;
}

struct XorShift32 {
  uint32_t state;
  explicit XorShift32(uint32_t seed) : state(seed ? seed : 0xA5A5A5A5u) {}

  uint32_t next() {
    uint32_t x = state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    state = x;
    return x;
  }
};

bool is_ascii_key(const std::string& key, std::string& error) {
  if (key.size() > 64) {
    error = "密钥长度不能超过64字符";
    return false;
  }
  for (unsigned char c : key) {
    if (c > 0x7F) {
      error = "密钥必须是ASCII";
      return false;
    }
  }
  return true;
}

// 编码单个5bit符号（0-31）为GBK字符
std::string encode_symbol(int val) {
  std::string out;
  if (val < 16) {
    out.append(kCharsGBK[val], kGBKCharSize);
  } else {
    out.append(kCharsGBK[val - 16], kGBKCharSize);
    out += kTilde;
  }
  return out;
}

// 将5字节编码为8个符号（40bit = 8×5bit）
std::string encode_quintet(const unsigned char* bytes) {
  std::string out;
  // 40bit = 5字节，分成8个5bit
  // byte0: [7:3] -> sym0, [2:0] + byte1[7:6] -> sym1
  // byte1: [5:1] -> sym2, [0] + byte2[7:4] -> sym3
  // byte2: [3:0] + byte3[7] -> sym4, byte3[6:2] -> sym5
  // byte3: [1:0] + byte4[7:5] -> sym6, byte4[4:0] -> sym7
  int sym0 = (bytes[0] >> 3) & 0x1F;
  int sym1 = ((bytes[0] & 0x07) << 2) | ((bytes[1] >> 6) & 0x03);
  int sym2 = (bytes[1] >> 1) & 0x1F;
  int sym3 = ((bytes[1] & 0x01) << 4) | ((bytes[2] >> 4) & 0x0F);
  int sym4 = ((bytes[2] & 0x0F) << 1) | ((bytes[3] >> 7) & 0x01);
  int sym5 = (bytes[3] >> 2) & 0x1F;
  int sym6 = ((bytes[3] & 0x03) << 3) | ((bytes[4] >> 5) & 0x07);
  int sym7 = bytes[4] & 0x1F;

  out += encode_symbol(sym0);
  out += encode_symbol(sym1);
  out += encode_symbol(sym2);
  out += encode_symbol(sym3);
  out += encode_symbol(sym4);
  out += encode_symbol(sym5);
  out += encode_symbol(sym6);
  out += encode_symbol(sym7);
  return out;
}

// 解码单个GBK符号，返回值0-31，失败返回-1
int decode_symbol(const std::string& input, size_t& pos) {
  if (pos + kGBKCharSize > input.size()) return -1;

  int base = -1;
  for (int d = 0; d < 16; ++d) {
    if (input.compare(pos, kGBKCharSize, kCharsGBK[d], kGBKCharSize) == 0) {
      base = d;
      break;
    }
  }
  if (base < 0) return -1;

  pos += kGBKCharSize;

  // 检查是否有~修饰符
  if (pos < input.size() && input[pos] == kTilde) {
    pos += 1;
    return base + 16;
  }
  return base;
}

// 从8个符号解码为5字节
bool decode_quintet(const std::string& input, size_t& pos,
                    unsigned char* bytes) {
  int syms[8];
  for (int i = 0; i < 8; ++i) {
    syms[i] = decode_symbol(input, pos);
    if (syms[i] < 0) return false;
  }

  // 还原5字节
  bytes[0] = static_cast<unsigned char>((syms[0] << 3) | (syms[1] >> 2));
  bytes[1] = static_cast<unsigned char>(((syms[1] & 0x03) << 6) |
                                        (syms[2] << 1) | (syms[3] >> 4));
  bytes[2] =
      static_cast<unsigned char>(((syms[3] & 0x0F) << 4) | (syms[4] >> 1));
  bytes[3] = static_cast<unsigned char>(((syms[4] & 0x01) << 7) |
                                        (syms[5] << 2) | (syms[6] >> 3));
  bytes[4] = static_cast<unsigned char>(((syms[6] & 0x07) << 5) | syms[7]);
  return true;
}

// 编码：首字节存长度，数据按5字节一组编码
std::string encode_bytes(const std::string& input) {
  size_t data_len = input.size();

  // 总字节数：1字节长度 + 数据
  size_t total_bytes = 1 + data_len;

  // 对齐到5字节的倍数
  size_t aligned_bytes = ((total_bytes + 4) / 5) * 5;

  // 构建待编码的字节数组
  std::vector<unsigned char> bytes(aligned_bytes, 0);
  bytes[0] = static_cast<unsigned char>(data_len & 0xFF);
  for (size_t i = 0; i < data_len; ++i) {
    bytes[i + 1] = static_cast<unsigned char>(input[i]);
  }

  // 每5字节编码为8个符号
  std::string out;
  for (size_t i = 0; i < aligned_bytes; i += 5) {
    out += encode_quintet(&bytes[i]);
  }

  return out;
}

Result decode_bytes(const std::string& input, std::string& out) {
  out.clear();

  if (input.empty()) {
    return Result::Err("输入太短");
  }

  // 解码所有字节
  std::vector<unsigned char> bytes;
  size_t pos = 0;

  while (pos < input.size()) {
    unsigned char quintet[5];
    if (!decode_quintet(input, pos, quintet)) {
      return Result::Err("非法猫叫片段");
    }
    for (int i = 0; i < 5; ++i) {
      bytes.push_back(quintet[i]);
    }
  }

  if (bytes.empty()) {
    return Result::Err("输入太短");
  }

  // 第一字节是长度
  size_t data_len = bytes[0];
  if (data_len > bytes.size() - 1) {
    return Result::Err("长度字段非法");
  }

  // 提取数据
  for (size_t i = 0; i < data_len; ++i) {
    out.push_back(static_cast<char>(bytes[i + 1]));
  }

  return Result::Ok("");
}

// XOR加密/解密（对称操作）：每字节与PRNG输出异或
std::string xor_transform(const std::string& input, const std::string& key) {
  uint32_t seed = fnv1a_32(key);
  XorShift32 prng(seed);

  std::string out;
  out.reserve(input.size());

  for (unsigned char c : input) {
    uint32_t k = prng.next() & 0xFFu;
    unsigned char enc = c ^ static_cast<unsigned char>(k);
    out.push_back(static_cast<char>(enc));
  }

  return out;
}

}  // namespace

Result encrypt(const std::string& input, const std::string& key) {
  std::string k = key.empty() ? kDefaultKey : key;
  std::string error;

  if (!is_ascii_key(k, error)) {
    return Result::Err(error);
  }

  // 1. 先压缩
  std::string compressed = lz_compress(input);

  // 如果压缩后更大，使用原始数据（首字节标记：0=未压缩，1=已压缩）
  std::string data;
  if (compressed.size() < input.size()) {
    data.push_back('\x01');  // 已压缩标记
    data += compressed;
  } else {
    data.push_back('\x00');  // 未压缩标记
    data += input;
  }

  if (data.size() > 255) {
    return Result::Err("数据太长（压缩后最大254字节）");
  }

  // 2. XOR加密
  std::string enc = xor_transform(data, k);

  // 3. 编码为GBK猫叫，然后转为UTF-8输出
  std::string gbk_encoded = encode_bytes(enc);
  return Result::Ok(gbk_to_utf8(gbk_encoded));
}

Result decrypt(const std::string& input, const std::string& key) {
  std::string k = key.empty() ? kDefaultKey : key;
  std::string error;

  if (!is_ascii_key(k, error)) {
    return Result::Err(error);
  }

  // 1. 将UTF-8输入转为GBK，再解码
  std::string gbk_input = utf8_to_gbk(input);
  std::string decoded;
  Result res = decode_bytes(gbk_input, decoded);
  if (!res.ok) {
    return res;
  }

  // 2. XOR解密
  std::string dec = xor_transform(decoded, k);

  if (dec.empty()) {
    return Result::Err("解密数据为空");
  }

  // 3. 检查压缩标记并解压
  char flag = dec[0];
  std::string payload = dec.substr(1);

  if (flag == '\x01') {
    // 已压缩，需要解压
    bool ok;
    std::string decompressed = lz_decompress(payload, ok);
    if (!ok) {
      return Result::Err("解压失败");
    }
    return Result::Ok(decompressed);
  } else {
    // 未压缩
    return Result::Ok(payload);
  }
}

}  // namespace meowcrypto
