#include "meow_crypto.h"

#include <sstream>
#include <string>
#include <vector>

namespace meowcrypto {

namespace {

const std::string kDefaultKey = "12#$";
// 16个字符，每个承载4bit（十六进制），2个汉字=8bit=1字节
// 信息密度是原来的2倍！
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

// 将字节编码为2个猫叫字符（每4bit一个字符，十六进制）
std::string encode_byte(unsigned char c) {
  std::string out;
  // 高4位 + 低4位
  out += kChars[(c >> 4) & 0xF];
  out += kChars[c & 0xF];
  return out;
}

// 从2个猫叫字符解码为1字节
bool decode_byte(const std::string& input, size_t pos, unsigned char& out) {
  out = 0;
  const size_t char_size = kChars[0].size();  // 3 bytes per UTF-8 char

  // 解码高4位
  if (pos + char_size > input.size()) return false;
  int hi = -1;
  for (int d = 0; d < 16; ++d) {
    if (input.compare(pos, char_size, kChars[d]) == 0) {
      hi = d;
      break;
    }
  }
  if (hi < 0) return false;

  // 解码低4位
  pos += char_size;
  if (pos + char_size > input.size()) return false;
  int lo = -1;
  for (int d = 0; d < 16; ++d) {
    if (input.compare(pos, char_size, kChars[d]) == 0) {
      lo = d;
      break;
    }
  }
  if (lo < 0) return false;

  out = static_cast<unsigned char>((hi << 4) | lo);
  return true;
}

// 编码：首字节存长度，然后数据，最后补齐到2的倍数
std::string encode_bytes(const std::string& input) {
  // 计算需要的总字节数（1字节长度 + 数据）
  size_t data_len = input.size();
  size_t total_bytes = 1 + data_len;  // 长度字节 + 数据

  // 对齐到2字节的倍数（每字节=2个汉字，2字节=4汉字）
  size_t aligned_bytes = ((total_bytes + 1) / 2) * 2;
  if (aligned_bytes == 0) aligned_bytes = 2;

  std::string out;

  // 第一字节：原始数据长度（最大支持255字节）
  out += encode_byte(static_cast<unsigned char>(data_len & 0xFF));

  // 数据字节
  for (unsigned char c : input) {
    out += encode_byte(c);
  }

  // 填充字节（用0填充）
  for (size_t i = total_bytes; i < aligned_bytes; ++i) {
    out += encode_byte(0);
  }

  return out;
}

Result decode_bytes(const std::string& input, std::string& out) {
  out.clear();

  // 每个汉字3字节（UTF-8），每字节需要2个汉字
  const size_t char_size = kChars[0].size();        // 3
  const size_t byte_chars = 2;                      // 2个汉字=1字节
  const size_t byte_size = char_size * byte_chars;  // 6

  if (input.size() < byte_size) {
    return Result::Err("输入太短");
  }

  // 检查输入长度是否为6的倍数（2个汉字的倍数）
  if (input.size() % byte_size != 0) {
    return Result::Err("输入长度非法");
  }

  // 解码第一字节：原始数据长度
  unsigned char len_byte;
  if (!decode_byte(input, 0, len_byte)) {
    return Result::Err("非法猫叫片段");
  }
  size_t data_len = len_byte;

  // 检查数据长度是否合理
  size_t total_bytes = input.size() / byte_size;
  if (data_len > total_bytes - 1) {
    return Result::Err("长度字段非法");
  }

  // 解码数据字节
  for (size_t i = 0; i < data_len; ++i) {
    unsigned char c;
    if (!decode_byte(input, (i + 1) * byte_size, c)) {
      return Result::Err("非法猫叫片段");
    }
    out.push_back(static_cast<char>(c));
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
