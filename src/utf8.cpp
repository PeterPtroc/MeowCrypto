#include "utf8.h"

namespace meowcrypto::utf8 {

static bool is_valid_scalar(uint32_t cp) {
  return cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);
}

bool decode(const std::string& input, std::vector<uint32_t>& out,
            std::string& error) {
  out.clear();
  const unsigned char* s = reinterpret_cast<const unsigned char*>(input.data());
  size_t i = 0;
  size_t n = input.size();

  while (i < n) {
    unsigned char c = s[i];
    uint32_t cp = 0;
    size_t len = 0;

    if (c <= 0x7F) {
      cp = c;
      len = 1;
    } else if ((c >> 5) == 0x6) {
      cp = c & 0x1F;
      len = 2;
    } else if ((c >> 4) == 0xE) {
      cp = c & 0x0F;
      len = 3;
    } else if ((c >> 3) == 0x1E) {
      cp = c & 0x07;
      len = 4;
    } else {
      error = "非法UTF-8起始字节";
      return false;
    }

    if (i + len > n) {
      error = "UTF-8序列长度不足";
      return false;
    }

    for (size_t j = 1; j < len; ++j) {
      unsigned char cc = s[i + j];
      if ((cc >> 6) != 0x2) {
        error = "非法UTF-8续字节";
        return false;
      }
      cp = (cp << 6) | (cc & 0x3F);
    }

    // Check overlong
    if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) ||
        (len == 4 && cp < 0x10000)) {
      error = "UTF-8过长编码";
      return false;
    }

    if (!is_valid_scalar(cp)) {
      error = "非法Unicode码点";
      return false;
    }

    out.push_back(cp);
    i += len;
  }

  return true;
}

bool encode(const std::vector<uint32_t>& codepoints, std::string& out,
            std::string& error) {
  out.clear();
  for (uint32_t cp : codepoints) {
    if (!is_valid_scalar(cp)) {
      error = "非法Unicode码点";
      return false;
    }

    if (cp <= 0x7F) {
      out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }
  return true;
}

}  // namespace meowcrypto::utf8
