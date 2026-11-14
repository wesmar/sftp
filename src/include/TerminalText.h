#pragma once

#include <string>
#include <string_view>

// Text a remote shell writes to a pseudo-terminal carries control sequences
// besides the output itself: colours, bracketed-paste switches, window titles
// and, on systemd 257+ hosts (Ubuntu 25.10, Fedora 42), OSC 3008 context
// records around every prompt. These helpers return the plain text.
namespace terminal_text {

// Removes ECMA-48 control sequences: CSI (ESC [ ... final), OSC (ESC ] ...
// terminated by BEL or ST), DCS/SOS/PM/APC strings (ESC P/X/^/_ ... ST) and
// the short ESC forms (ESC ( B, ESC =, ...). BEL is dropped; all other bytes,
// including the 0x80-0xFF bytes of UTF-8 text, are kept. An unterminated
// sequence at the end of the input is dropped.
std::string StripControls(std::string_view in);

// Decodes the \ooo octal escapes some ls builds use for unusual bytes.
std::string DecodeOctalEscapes(std::string_view in);

} // namespace terminal_text
