#include "TextConversion.h"

namespace text_conversion {

size_t LfToCrLf::Convert(const char* data, size_t len, std::vector<char>& out)
{
    const size_t before = out.size();
    out.reserve(before + 2 * len);
    for (size_t i = 0; i < len; ++i) {
        const char c = data[i];
        if (c == '\n' && !lastWasCr_)
            out.push_back('\r');
        out.push_back(c);
        lastWasCr_ = (c == '\r');
    }
    return out.size() - before;
}

template <typename Emit>
size_t CrLfToLf::Run(const char* data, size_t len, Emit&& emit)
{
    size_t emitted = 0;
    for (size_t i = 0; i < len; ++i) {
        const char c = data[i];
        if (pendingCr_) {
            pendingCr_ = false;
            if (c != '\n') {
                emit('\r');
                ++emitted;
            }
        }
        if (c == '\r') {
            pendingCr_ = true;
            continue;
        }
        emit(c);
        ++emitted;
    }
    return emitted;
}

size_t CrLfToLf::Convert(const char* data, size_t len, std::vector<char>& out)
{
    out.reserve(out.size() + len);
    return Run(data, len, [&out](char c) { out.push_back(c); });
}

size_t CrLfToLf::Finish(std::vector<char>& out)
{
    if (!pendingCr_)
        return 0;
    pendingCr_ = false;
    out.push_back('\r');
    return 1;
}

size_t CrLfToLf::Count(const char* data, size_t len)
{
    return Run(data, len, [](char) {});
}

size_t CrLfToLf::FinishCount()
{
    const size_t held = pendingCr_ ? 1 : 0;
    pendingCr_ = false;
    return held;
}

} // namespace text_conversion
