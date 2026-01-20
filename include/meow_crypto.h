#pragma once

#include <string>

namespace meowcrypto {

struct Result {
  bool ok;
  std::string value;
  std::string error;

  static Result Ok(std::string v) { return {true, std::move(v), ""}; }
  static Result Err(std::string e) { return {false, "", std::move(e)}; }
};

Result encrypt(const std::string& input, const std::string& key = "");
Result decrypt(const std::string& input, const std::string& key = "");

}  // namespace meowcrypto
