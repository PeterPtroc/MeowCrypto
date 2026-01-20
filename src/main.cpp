#include <iostream>
#include <string>
#include <vector>

#include "meow_crypto.h"

namespace {

void print_usage() {
  std::cerr << "用法: meowcrypto --mode <encrypt|decrypt> [--key <ascii密钥>] "
               "<字符串>\n";
  std::cerr << "示例: meowcrypto --mode encrypt --key 12#$ \"你好 世界\"\n";
}

bool starts_with(const std::string& s, const std::string& prefix) {
  return s.rfind(prefix, 0) == 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    print_usage();
    return 1;
  }

  std::string mode;
  std::string key;
  std::vector<std::string> text_parts;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--mode") {
      if (i + 1 >= argc) {
        std::cerr << "缺少--mode参数\n";
        return 1;
      }
      mode = argv[++i];
    } else if (arg == "--key") {
      if (i + 1 >= argc) {
        std::cerr << "缺少--key参数\n";
        return 1;
      }
      key = argv[++i];
    } else if (starts_with(arg, "--")) {
      std::cerr << "未知参数: " << arg << "\n";
      return 1;
    } else {
      text_parts.push_back(arg);
    }
  }

  if (mode != "encrypt" && mode != "decrypt") {
    std::cerr << "--mode必须是encrypt或decrypt\n";
    return 1;
  }

  if (text_parts.empty()) {
    std::cerr << "缺少待处理字符串\n";
    return 1;
  }

  std::string text = text_parts[0];
  for (size_t i = 1; i < text_parts.size(); ++i) {
    text += " ";
    text += text_parts[i];
  }

  meowcrypto::Result result = (mode == "encrypt")
                                  ? meowcrypto::encrypt(text, key)
                                  : meowcrypto::decrypt(text, key);

  if (!result.ok) {
    std::cerr << result.error << "\n";
    return 1;
  }

  std::cout << result.value << "\n";
  return 0;
}
