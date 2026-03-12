#include "global.h"
#include "AuthMethodParser.h"
#include "SftpInternal.h"
#include <cctype>
#include <string_view>

namespace {

std::string_view TrimWhitespace(std::string_view value) noexcept
{
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos)
        return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

int AuthMethodToFlag(std::string_view method) noexcept
{
    if (method == "password")
        return SSH_AUTH_PASSWORD;
    if (method == "keyboard-interactive")
        return SSH_AUTH_KEYBOARD;
    if (method == "publickey")
        return SSH_AUTH_PUBKEY;
    return 0;
}

} // anonymous namespace

int ParseAuthMethodsFromUserauthList(const char* userauthlist) noexcept
{
    if (!userauthlist || !userauthlist[0])
        return 0;

    std::string_view list(userauthlist);
    int result = 0;

    size_t pos = 0;
    while (pos < list.size()) {
        const auto comma = list.find(',', pos);
        const auto token = TrimWhitespace(list.substr(pos, comma - pos));
        if (!token.empty()) {
            // Convert to lowercase for comparison
            std::string lower(token.size(), '\0');
            for (size_t i = 0; i < token.size(); ++i)
                lower[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(token[i])));
            result |= AuthMethodToFlag(lower);
        }
        if (comma == std::string_view::npos)
            break;
        pos = comma + 1;
    }
    return result;
}
