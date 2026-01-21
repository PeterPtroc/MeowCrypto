#include "meow_crypto.h"

#include <sstream>
#include <string>
#include <vector>

namespace meowcrypto {

namespace {

const std::string kDefaultKey = "12#$";
// 16个基础字符 + "~"修饰符 = 32个符号（5bit）
// 编码方式：8个符号 = 40bit = 5字节
// 相比原来16进制（2符号=1字节），密度提升25%！
const std::string kChars[16] = {
    "喵",  // 0  - 基础猫叫
    "呜",  // 1  - 低沉叫声
    "咪",  // 2  - 温柔叫声
    "嗷",  // 3  - 大声叫
    "呼",  // 4  - 呼噜声
    "噜",  // 5  - 呼噜声变体
    "哈",  // 6  - 哈气声
    "嘶",  // 7  - 嘶叫
    "嗯",  // 8  - 撒娇声
    "哼",  // 9  - 不满声
    "唔",  // A  - 困倦声
    "啾",  // B  - 小叫声
    "嘤",  // C  - 委屈声
    "咕",  // D  - 咕噜声
    "呦",  // E  - 呼唤声
    "吼",  // F  - 凶猛叫
};
const std::string kTilde = "~";  // 修饰符，表示+16

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

// 编码单个5bit符号（0-31）
std::string encode_symbol(int val) {
  std::string out;
  if (val < 16) {
    out += kChars[val];
  } else {
    out += kChars[val - 16];
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

// 解码单个符号，返回值0-31，失败返回-1
int decode_symbol(const std::string& input, size_t& pos) {
  const size_t char_size = kChars[0].size();  // 3 bytes per UTF-8 char

  if (pos + char_size > input.size()) return -1;

  int base = -1;
  for (int d = 0; d < 16; ++d) {
    if (input.compare(pos, char_size, kChars[d]) == 0) {
      base = d;
      break;
    }
  }
  if (base < 0) return -1;

  pos += char_size;

  // 检查是否有~修饰符
  if (pos < input.size() && input[pos] == '~') {
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

  if (input.size() > 255) {
    return Result::Err("输入太长（最大255字节）");
  }

  std::string enc = xor_transform(input, k);
  return Result::Ok(encode_bytes(enc));
}

Result decrypt(const std::string& input, const std::string& key) {
  std::string k = key.empty() ? kDefaultKey : key;
  std::string error;

  if (!is_ascii_key(k, error)) {
    return Result::Err(error);
  }

  std::string decoded;
  Result res = decode_bytes(input, decoded);
  if (!res.ok) {
    return res;
  }

  std::string dec = xor_transform(decoded, k);
  return Result::Ok(dec);
}

}  // namespace meowcrypto
