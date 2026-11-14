#include "TerminalText.h"

namespace terminal_text {

namespace {

constexpr char kEsc = '\x1B';
constexpr char kBel = '\x07';

// Index just past a string control sequence (OSC, DCS, SOS, PM, APC) whose
// body starts at `i`; ST is ESC '\', and OSC may also end with BEL.
size_t SkipControlString(std::string_view s, size_t i, bool belEnds)
{
    while (i < s.size()) {
        if (belEnds && s[i] == kBel)
            return i + 1;
        if (s[i] == kEsc && i + 1 < s.size() && s[i + 1] == '\\')
            return i + 2;
        ++i;
    }
    return s.size();
}

} // namespace

std::string StripControls(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        const char c = s[i];
        if (c == kBel) {
            ++i;
            continue;
        }
        if (c != kEsc) {
            out.push_back(c);
            ++i;
            continue;
        }
        if (i + 1 >= s.size())
            break;
        const unsigned char next = static_cast<unsigned char>(s[i + 1]);
        if (next == '[') {
            // CSI: parameter bytes 0x30-0x3F, intermediates 0x20-0x2F, final 0x40-0x7E.
            size_t j = i + 2;
            while (j < s.size() && static_cast<unsigned char>(s[j]) >= 0x30 && static_cast<unsigned char>(s[j]) <= 0x3F)
                ++j;
            while (j < s.size() && static_cast<unsigned char>(s[j]) >= 0x20 && static_cast<unsigned char>(s[j]) <= 0x2F)
                ++j;
            i = (j < s.size() && static_cast<unsigned char>(s[j]) >= 0x40 && static_cast<unsigned char>(s[j]) <= 0x7E) ? j + 1
                                                                                                                    : j;
        } else if (next == ']') {
            i = SkipControlString(s, i + 2, true);
        } else if (next == 'P' || next == 'X' || next == '^' || next == '_') {
            i = SkipControlString(s, i + 2, false);
        } else if (next >= 0x20 && next <= 0x2F) {
            // ESC, intermediates, final byte: ESC ( B, ESC # 8, ...
            size_t j = i + 1;
            while (j < s.size() && static_cast<unsigned char>(s[j]) >= 0x20 && static_cast<unsigned char>(s[j]) <= 0x2F)
                ++j;
            i = j < s.size() ? j + 1 : j;
        } else {
            // Two-byte forms: ESC =, ESC >, ESC 7, ESC M, ESC c, ...
            i += 2;
        }
    }
    return out;
}

std::string DecodeOctalEscapes(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 3 < s.size() &&
            s[i + 1] >= '0' && s[i + 1] <= '3' && s[i + 2] >= '0' && s[i + 2] <= '7' && s[i + 3] >= '0' && s[i + 3] <= '7') {
            out.push_back(static_cast<char>((s[i + 1] - '0') * 64 + (s[i + 2] - '0') * 8 + (s[i + 3] - '0')));
            i += 3;
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

} // namespace terminal_text
