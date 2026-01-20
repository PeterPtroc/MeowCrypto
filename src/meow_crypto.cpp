#include "meow_crypto.h"

#include <sstream>
#include <string>
#include <vector>

namespace meowcrypto {

namespace {

const std::string kDefaultKey = "12#$";
const std::string kSeparator = "～";  // 全角波浪线作为字符分隔

// 16个token，每个承载4bit，更高信息密度
// 使用无歧义的token集合：每个token都以不同的结尾字符结束
const std::vector<std::string> kTokens = {
    "喵.",    // 0
    "呜.",    // 1
    "喵~",    // 2
    "呜~",    // 3
    "喵喵.",  // 4
    "呜呜.",  // 5
    "喵呜.",  // 6
    "呜喵.",  // 7
    "喵!",    // 8
    "呜!",    // 9
    "喵喵~",  // 10
    "呜呜~",  // 11
    "喵呜~",  // 12
    "呜喵~",  // 13
    "喵喵!",  // 14
    "呜呜!",  // 15
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

// 按字节编码：每字节用2个token（高4bit + 低4bit）
// 字符之间用全角波浪线分隔，更像猫叫
std::string encode_bytes(const std::string& input) {
  std::ostringstream oss;
  for (size_t i = 0; i < input.size(); ++i) {
    unsigned char c = static_cast<unsigned char>(input[i]);
    int hi = (c >> 4) & 0x0F;
    int lo = c & 0x0F;
    oss << kTokens[hi] << kTokens[lo];
    if (i + 1 < input.size()) {
      oss << kSeparator;
    }
  }
  return oss.str();
}

// 查找token并返回其索引（0-15），失败返回-1
// 使用最长匹配优先策略
int find_token(const std::string& input, size_t pos, size_t& consumed) {
  size_t max_len = 0;
  int best_idx = -1;

  for (int idx = 0; idx < 16; ++idx) {
    const std::string& tok = kTokens[idx];
    if (tok.size() > max_len && pos + tok.size() <= input.size() &&
        input.compare(pos, tok.size(), tok) == 0) {
      max_len = tok.size();
      best_idx = idx;
    }
  }

  consumed = max_len;
  return best_idx;
}

Result decode_bytes(const std::string& input, std::string& out) {
  out.clear();
  size_t pos = 0;
  size_t n = input.size();

  while (pos < n) {
    // 跳过分隔符
    if (input.compare(pos, kSeparator.size(), kSeparator) == 0) {
      pos += kSeparator.size();
      continue;
    }

    // 读取高4bit
    size_t consumed = 0;
    int hi = find_token(input, pos, consumed);
    if (hi < 0) {
      return Result::Err("非法喵呜片段");
    }
    pos += consumed;

    // 跳过可能的分隔符（不应该出现在字节中间，但容错）
    if (pos < n && input.compare(pos, kSeparator.size(), kSeparator) == 0) {
      return Result::Err("分隔符位置非法");
    }

    // 读取低4bit
    int lo = find_token(input, pos, consumed);
    if (lo < 0) {
      return Result::Err("非法喵呜片段");
    }
    pos += consumed;

    unsigned char c = static_cast<unsigned char>((hi << 4) | lo);
    out.push_back(static_cast<char>(c));
  }

  return Result::Ok("");
}

// 按字节加密：每字节与PRNG输出异或
std::string encrypt_bytes(const std::string& input, const std::string& key) {
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

// 解密与加密相同（XOR对称）
std::string decrypt_bytes(const std::string& input, const std::string& key) {
  return encrypt_bytes(input, key);
}

}  // namespace

Result encrypt(const std::string& input, const std::string& key) {
  std::string k = key.empty() ? kDefaultKey : key;
  std::string error;

  if (!is_ascii_key(k, error)) {
    return Result::Err(error);
  }

  std::string enc = encrypt_bytes(input, k);
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

  std::string dec = decrypt_bytes(decoded, k);
  return Result::Ok(dec);
}

}  // namespace meowcrypto
