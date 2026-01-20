#pragma once

#include <string>
#include <vector>

namespace meowcrypto::utf8 {

bool decode(const std::string& input, std::vector<uint32_t>& out,
            std::string& error);
bool encode(const std::vector<uint32_t>& codepoints, std::string& out,
            std::string& error);

}  // namespace meowcrypto::utf8
