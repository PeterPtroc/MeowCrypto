#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "meow_crypto.h"
#include "utf8.h"

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

  // 超过255字节应该失败
  std::string too_long(256, 'x');
  auto res = meowcrypto::encrypt(too_long);
  require(!res.ok, "input > 255 bytes should fail");
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
// UTF-8 编解码测试
// ========================
void test_utf8_codec() {
  std::cout << "== UTF-8 编解码测试 ==\n";

  std::vector<uint32_t> codepoints;
  std::string error;
  std::string encoded;

  // 1字节字符 (ASCII)
  require(meowcrypto::utf8::decode("ABC", codepoints, error),
          "decode ASCII should succeed");
  require(codepoints.size() == 3 && codepoints[0] == 'A',
          "ASCII decode correct");

  // 2字节字符 (拉丁扩展等)
  codepoints.clear();
  require(meowcrypto::utf8::decode("é", codepoints, error),
          "decode 2-byte char should succeed");
  require(codepoints.size() == 1 && codepoints[0] == 0xE9,
          "2-byte decode correct");

  // 3字节字符 (中文)
  codepoints.clear();
  require(meowcrypto::utf8::decode("中", codepoints, error),
          "decode 3-byte char should succeed");
  require(codepoints.size() == 1 && codepoints[0] == 0x4E2D,
          "3-byte decode correct");

  // 4字节字符 (emoji)
  codepoints.clear();
  require(meowcrypto::utf8::decode("😀", codepoints, error),
          "decode 4-byte char should succeed");
  require(codepoints.size() == 1 && codepoints[0] == 0x1F600,
          "4-byte decode correct");

  // 编码测试
  codepoints = {'A', 0xE9, 0x4E2D, 0x1F600};
  require(meowcrypto::utf8::encode(codepoints, encoded, error),
          "encode mixed should succeed");
  require(encoded == "Aé中😀", "encode result correct");

  // 往返测试
  std::string test_str = "Hello 你好 😀";
  codepoints.clear();
  require(meowcrypto::utf8::decode(test_str, codepoints, error),
          "decode mixed string");
  require(meowcrypto::utf8::encode(codepoints, encoded, error), "encode back");
  require(encoded == test_str, "UTF-8 roundtrip should match");
}

// ========================
// UTF-8 错误处理测试
// ========================
void test_utf8_errors() {
  std::cout << "== UTF-8 错误处理测试 ==\n";

  std::vector<uint32_t> codepoints;
  std::string error;
  std::string encoded;

  // 非法起始字节 (0x80-0xBF 是续字节，不能作为起始)
  error.clear();
  require(!meowcrypto::utf8::decode("\x80", codepoints, error),
          "invalid start byte should fail");
  require(!error.empty(), "error message should be set");

  // 不完整的多字节序列
  error.clear();
  require(!meowcrypto::utf8::decode("\xC2", codepoints, error),
          "incomplete 2-byte should fail");

  error.clear();
  require(!meowcrypto::utf8::decode("\xE4\xB8", codepoints, error),
          "incomplete 3-byte should fail");

  error.clear();
  require(!meowcrypto::utf8::decode("\xF0\x9F\x98", codepoints, error),
          "incomplete 4-byte should fail");

  // 非法续字节
  error.clear();
  require(!meowcrypto::utf8::decode("\xC2\x00", codepoints, error),
          "invalid continuation should fail");

  // 过长编码 (用2字节编码1字节字符)
  error.clear();
  require(!meowcrypto::utf8::decode("\xC0\x80", codepoints, error),
          "overlong encoding should fail");

  // 代理对范围 (0xD800-0xDFFF) - 非法Unicode
  codepoints = {0xD800};
  error.clear();
  require(!meowcrypto::utf8::encode(codepoints, encoded, error),
          "surrogate should fail");

  // 超出Unicode范围
  codepoints = {0x110000};
  error.clear();
  require(!meowcrypto::utf8::encode(codepoints, encoded, error),
          "out of range should fail");
}

// ========================
// 输出格式验证测试
// ========================
void test_output_format() {
  std::cout << "== 输出格式验证测试 ==\n";

  auto enc = meowcrypto::encrypt("a", "12#$");
  require(enc.ok, "encryption should succeed");

  // 输出应该只包含喵呜咪嗷四个字符
  std::string valid_chars = "喵呜咪嗷";
  bool all_valid = true;
  std::string output = enc.value;
  size_t i = 0;
  while (i < output.size()) {
    bool found = false;
    for (const char* vc : {"喵", "呜", "咪", "嗷"}) {
      size_t len = strlen(vc);
      if (output.compare(i, len, vc) == 0) {
        found = true;
        i += len;
        break;
      }
    }
    if (!found) {
      all_valid = false;
      break;
    }
  }
  require(all_valid, "output should only contain valid meow characters");

  // 输出长度应该是12的倍数（每字节4个汉字，每汉字3字节UTF-8）
  require(enc.value.size() % 12 == 0,
          "output size should be multiple of 12 bytes");
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
  test_utf8_codec();
  test_utf8_errors();
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
