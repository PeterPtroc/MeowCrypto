#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "meow_crypto.h"

namespace {

int g_failed = 0;
int g_passed = 0;

void require(bool cond, const std::string& msg) {
  if (!cond) {
    ++g_failed;
    std::cerr << "[FAIL] " << msg << "\n";
  } else {
    ++g_passed;
  }
}

void test_roundtrip(const std::string& text, const std::string& key = "") {
  auto enc = meowcrypto::encrypt(text, key);
  require(enc.ok, "encrypt should succeed for: \"" + text + "\"");
  if (!enc.ok) return;

  auto dec = meowcrypto::decrypt(enc.value, key);
  require(dec.ok, "decrypt should succeed for: \"" + text + "\"");
  if (!dec.ok) return;

  require(dec.value == text, "roundtrip mismatch for: \"" + text + "\"");
}

// ========================
// 基础往返测试
// ========================
void test_basic_roundtrip() {
  std::cout << "== 基础往返测试 ==\n";

  // 英文字符串
  test_roundtrip("hello");
  test_roundtrip("Hello World!");
  test_roundtrip("The quick brown fox jumps over the lazy dog");

  // 中文字符串
  test_roundtrip("你好 世界");
  test_roundtrip("带空格的 中文 字符串");
  test_roundtrip("虾米是小男娘");

  // 空字符串
  test_roundtrip("");

  // 单字符
  test_roundtrip("a");
  test_roundtrip("喵");

  // 特殊字符
  test_roundtrip("!@#$%^&*()_+-=[]{}|;':\",./<>?");
  test_roundtrip("\t\n\r");

  // 混合内容
  test_roundtrip("Hello你好World世界123");

  // emoji（4字节UTF-8）
  test_roundtrip("😀🎉🐱");
  test_roundtrip("Hello 😀 World");
}

// ========================
// 边界长度测试
// ========================
void test_boundary_lengths() {
  std::cout << "== 边界长度测试 ==\n";

  // 1字节
  test_roundtrip("x");

  // 几个特定长度
  test_roundtrip(std::string(10, 'a'));
  test_roundtrip(std::string(100, 'b'));
  test_roundtrip(std::string(200, 'c'));

  // 最大长度255字节
  test_roundtrip(std::string(255, 'z'));

  // 超过254字节不可压缩数据应该失败（因为加上1字节标记会超过255）
  // 使用随机数据确保不可压缩
  std::string too_long;
  for (int i = 0; i < 256; ++i) {
    too_long.push_back(static_cast<char>(i));
  }
  auto res = meowcrypto::encrypt(too_long);
  require(!res.ok, "input > 254 bytes (uncompressible) should fail");
  require(res.error.find("太长") != std::string::npos,
          "error should mention too long");
}

// ========================
// 密钥测试
// ========================
void test_key_handling() {
  std::cout << "== 密钥测试 ==\n";

  // 空密钥（使用默认）
  test_roundtrip("test with default key", "");

  // 自定义ASCII密钥
  test_roundtrip("test with custom key", "mySecretKey123");
  test_roundtrip("test with symbols", "!@#$%^&*");

  // 不同密钥应产生不同输出
  auto enc1 = meowcrypto::encrypt("hello", "key1");
  auto enc2 = meowcrypto::encrypt("hello", "key2");
  require(enc1.ok && enc2.ok, "both encryptions should succeed");
  require(enc1.value != enc2.value,
          "different keys should produce different ciphertexts");

  // 相同密钥应产生相同输出
  auto enc3 = meowcrypto::encrypt("hello", "sameKey");
  auto enc4 = meowcrypto::encrypt("hello", "sameKey");
  require(enc3.ok && enc4.ok, "both encryptions should succeed");
  require(enc3.value == enc4.value, "same key should produce same ciphertext");

  // 非ASCII密钥应失败
  auto bad_key = meowcrypto::encrypt("hi", "密钥");
  require(!bad_key.ok, "non-ascii key should fail");
  require(bad_key.error.find("ASCII") != std::string::npos,
          "error should mention ASCII");

  // 过长密钥应失败（>64字符）
  std::string long_key(65, 'a');
  auto bad_key2 = meowcrypto::encrypt("hi", long_key);
  require(!bad_key2.ok, "key > 64 chars should fail");

  // 64字符密钥应该可以
  std::string max_key(64, 'k');
  test_roundtrip("test with max length key", max_key);

  // 1字符密钥
  test_roundtrip("test with single char key", "x");
}

// ========================
// 错误的密文输入测试
// ========================
void test_invalid_ciphertext() {
  std::cout << "== 非法密文测试 ==\n";

  // 非法字符（不是喵呜咪嗷）
  auto bad_tok = meowcrypto::decrypt("喵啾咪嗷", "12#$");
  require(!bad_tok.ok, "invalid character should fail");

  // 长度不足（少于4个汉字=1字节）
  auto too_short = meowcrypto::decrypt("喵", "12#$");
  require(!too_short.ok, "too short input should fail");

  auto too_short2 = meowcrypto::decrypt("喵呜咪", "12#$");
  require(!too_short2.ok, "too short input (3 chars) should fail");

  // 长度不是4的倍数
  auto bad_len = meowcrypto::decrypt("喵呜咪嗷喵", "12#$");
  require(!bad_len.ok, "length not multiple of 4 chars should fail");

  // 空输入
  auto empty = meowcrypto::decrypt("", "12#$");
  require(!empty.ok, "empty input should fail");

  // 普通英文/数字（不是有效密文）
  auto ascii = meowcrypto::decrypt("hello", "12#$");
  require(!ascii.ok, "ASCII input should fail");

  // 错误密钥解密（不会失败，但结果不同）
  auto enc = meowcrypto::encrypt("hello", "key1");
  require(enc.ok, "encryption should succeed");
  auto dec_wrong = meowcrypto::decrypt(enc.value, "wrongkey");
  require(dec_wrong.ok,
          "decryption with wrong key should succeed (XOR is symmetric)");
  require(dec_wrong.value != "hello", "wrong key should produce wrong result");
}

// ========================
// 压缩效果测试
// ========================
void test_compression() {
  std::cout << "== 压缩效果测试 ==\n";

  // 重复内容应该被压缩
  std::string repeated = "abcabcabcabcabcabc";
  auto enc = meowcrypto::encrypt(repeated, "key");
  require(enc.ok, "encryption of repeated content should succeed");
  auto dec = meowcrypto::decrypt(enc.value, "key");
  require(dec.ok && dec.value == repeated, "roundtrip with compression");

  // 随机内容也应该正常工作
  std::string random_content = "hello world test 123";
  auto enc2 = meowcrypto::encrypt(random_content, "key");
  require(enc2.ok, "encryption of random content should succeed");
  auto dec2 = meowcrypto::decrypt(enc2.value, "key");
  require(dec2.ok && dec2.value == random_content,
          "roundtrip without much compression");
}

// ========================
// GBK/UTF-8 转换测试
// ========================
void test_encoding_conversion() {
  std::cout << "== GBK/UTF-8 转换测试 ==\n";

  // 测试包含中文字符的加密输出是否为有效UTF-8
  auto enc = meowcrypto::encrypt("test", "key");
  require(enc.ok, "encryption should succeed");

  // 输出应该是有效的UTF-8（能正常显示中文猫叫）
  // 检查输出不包含无效的UTF-8序列
  bool valid_utf8 = true;
  const std::string& out = enc.value;
  for (size_t i = 0; i < out.size();) {
    unsigned char c = static_cast<unsigned char>(out[i]);
    size_t len = 0;
    if ((c & 0x80) == 0)
      len = 1;
    else if ((c & 0xE0) == 0xC0)
      len = 2;
    else if ((c & 0xF0) == 0xE0)
      len = 3;
    else if ((c & 0xF8) == 0xF0)
      len = 4;
    else {
      valid_utf8 = false;
      break;
    }

    if (i + len > out.size()) {
      valid_utf8 = false;
      break;
    }
    for (size_t j = 1; j < len; ++j) {
      if ((static_cast<unsigned char>(out[i + j]) & 0xC0) != 0x80) {
        valid_utf8 = false;
        break;
      }
    }
    if (!valid_utf8) break;
    i += len;
  }
  require(valid_utf8, "output should be valid UTF-8");
}

// ========================
// 输出格式验证测试
// ========================
void test_output_format() {
  std::cout << "== 输出格式验证测试 ==\n";

  auto enc = meowcrypto::encrypt("a", "12#$");
  require(enc.ok, "encryption should succeed");

  // 输出应该只包含16个猫叫字符 + "~"修饰符
  bool all_valid = true;
  std::string output = enc.value;
  const char* valid_meows[] = {"喵", "呜", "咪", "嗷", "呼", "噜", "哈", "嘶",
                               "嗯", "哼", "唔", "啾", "嘤", "咕", "呦", "吼"};
  size_t i = 0;
  while (i < output.size()) {
    bool found = false;
    // 检查是否是猫叫字符
    for (const char* vc : valid_meows) {
      size_t len = strlen(vc);
      if (output.compare(i, len, vc) == 0) {
        found = true;
        i += len;
        // 检查是否跟随~修饰符
        if (i < output.size() && output[i] == '~') {
          i += 1;
        }
        break;
      }
    }
    if (!found) {
      all_valid = false;
      break;
    }
  }
  require(all_valid, "output should only contain valid meow characters");

  // 新编码：8个符号=5字节，每符号是1个汉字(3字节)+可选~(1字节)
  // 不再检查固定长度倍数，改为检查能否正确解密
  auto dec = meowcrypto::decrypt(enc.value, "12#$");
  require(dec.ok && dec.value == "a", "output format should be decodable");
}

// ========================
// 一致性测试
// ========================
void test_consistency() {
  std::cout << "== 一致性测试 ==\n";

  // 多次加密相同输入应得到相同结果
  for (int i = 0; i < 10; ++i) {
    auto enc = meowcrypto::encrypt("test consistency", "testkey");
    require(enc.ok, "encryption should succeed");

    static std::string first_result;
    if (i == 0) {
      first_result = enc.value;
    } else {
      require(enc.value == first_result,
              "multiple encryptions should be consistent");
    }
  }

  // 解密后应该和原文完全一致（包括空白字符）
  std::string with_whitespace = "  hello  \t\n  world  ";
  auto enc = meowcrypto::encrypt(with_whitespace, "key");
  require(enc.ok, "encryption should succeed");
  auto dec = meowcrypto::decrypt(enc.value, "key");
  require(dec.ok, "decryption should succeed");
  require(dec.value == with_whitespace,
          "whitespace should be preserved exactly");
}

// ========================
// 二进制数据测试
// ========================
void test_binary_data() {
  std::cout << "== 二进制数据测试 ==\n";

  // 包含NUL字节
  std::string with_nul = "hello\0world";
  with_nul.resize(11);  // 确保长度正确
  test_roundtrip(with_nul, "key");

  // 所有字节值 0-255
  std::string all_bytes;
  for (int i = 0; i < 256; ++i) {
    all_bytes.push_back(static_cast<char>(i));
  }
  // 这个超过255字节，所以分段测试
  test_roundtrip(all_bytes.substr(0, 128), "key1");
  test_roundtrip(all_bytes.substr(128, 127), "key2");

  // 高位字节
  std::string high_bytes;
  for (int i = 128; i < 256; ++i) {
    high_bytes.push_back(static_cast<char>(i));
  }
  test_roundtrip(high_bytes, "key");
}

}  // namespace

int main() {
  std::cout << "=== MeowCrypto 测试套件 ===\n\n";

  test_basic_roundtrip();
  test_boundary_lengths();
  test_key_handling();
  test_invalid_ciphertext();
  test_compression();
  test_encoding_conversion();
  test_output_format();
  test_consistency();
  test_binary_data();

  std::cout << "\n=== 测试结果 ===\n";
  std::cout << "通过: " << g_passed << "\n";
  std::cout << "失败: " << g_failed << "\n";

  if (g_failed == 0) {
    std::cout << "\n所有测试通过！\n";
    return 0;
  }

  std::cerr << "\n有 " << g_failed << " 个测试失败。\n";
  return 1;
}
