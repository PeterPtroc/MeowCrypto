#include <iostream>
#include <string>

#include "meow_crypto.h"

namespace {

int g_failed = 0;

void require(bool cond, const std::string& msg) {
  if (!cond) {
    ++g_failed;
    std::cerr << "[FAIL] " << msg << "\n";
  }
}

void test_roundtrip(const std::string& text, const std::string& key = "") {
  auto enc = meowcrypto::encrypt(text, key);
  require(enc.ok, "encrypt should succeed");
  if (!enc.ok) return;

  auto dec = meowcrypto::decrypt(enc.value, key);
  require(dec.ok, "decrypt should succeed");
  if (!dec.ok) return;

  require(dec.value == text, "roundtrip mismatch");
}

}  // namespace

int main() {
  test_roundtrip("hello");
  test_roundtrip("你好 世界");
  test_roundtrip("带空格的 中文 字符串");
  test_roundtrip("");  // 空串

  auto bad_key = meowcrypto::encrypt("hi", "密钥");
  require(!bad_key.ok, "non-ascii key should fail");

  std::string long_key(65, 'a');
  auto bad_key2 = meowcrypto::encrypt("hi", long_key);
  require(!bad_key2.ok, "too long key should fail");

  // 非法token测试（包含无效字符）
  auto bad_tok = meowcrypto::decrypt("喵啾", "12#$");
  require(!bad_tok.ok, "invalid token should fail");

  // 奇数token测试（一个字节需要2个token）
  auto bad_odd = meowcrypto::decrypt("喵", "12#$");
  require(!bad_odd.ok, "odd token count should fail");

  if (g_failed == 0) {
    std::cout << "All tests passed.\n";
    return 0;
  }

  std::cerr << g_failed << " tests failed.\n";
  return 1;
}
