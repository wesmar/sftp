#include "WindowsUserFeedback.h"
#include "PluginEntryPoints.h"
#include "UnicodeHelpers.h"
#include "fsplugin.h"
#include <array>
#include <vector>

static std::wstring MbToWide(const std::string& s)
{
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(), -1, nullptr, 0);
    if (len <= 0) {
        len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
        if (len <= 0) return {};
        std::wstring w(len - 1, L'\0');
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, w.data(), len);
        return w;
    }
    std::wstring w(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(), -1, w.data(), len);
    return w;
}

void WindowsUserFeedback::ShowError(const std::string& message, const std::string& title) {
    if (RequestProcW) {
        auto wmsg = MbToWide(message), wtitle = MbToWide(title);
        RequestProcW(PluginNumber, RT_MsgOK, wtitle.c_str(), wmsg.c_str(), nullptr, 0);
    } else if (RequestProc) {
        RequestProc(PluginNumber, RT_MsgOK, title.c_str(), message.c_str(), nullptr, 0);
    } else {
        auto wmsg = MbToWide(message), wtitle = MbToWide(title);
        MessageBoxW(parent_, wmsg.c_str(), wtitle.c_str(), MB_OK | MB_ICONSTOP);
    }
}

void WindowsUserFeedback::ShowMessage(const std::string& message, const std::string& title) {
    if (RequestProcW) {
        auto wmsg = MbToWide(message), wtitle = MbToWide(title);
        RequestProcW(PluginNumber, RT_MsgOK, wtitle.c_str(), wmsg.c_str(), nullptr, 0);
    } else if (RequestProc) {
        RequestProc(PluginNumber, RT_MsgOK, title.c_str(), message.c_str(), nullptr, 0);
    } else {
        auto wmsg = MbToWide(message), wtitle = MbToWide(title);
        MessageBoxW(parent_, wmsg.c_str(), wtitle.c_str(), MB_OK | MB_ICONINFORMATION);
    }
}

bool WindowsUserFeedback::AskYesNo(const std::string& message, const std::string& title) {
    if (RequestProcW) {
        auto wmsg = MbToWide(message), wtitle = MbToWide(title);
        return RequestProcW(PluginNumber, RT_MsgYesNo, wtitle.c_str(), wmsg.c_str(), nullptr, 0) != FALSE;
    } else if (RequestProc) {
        return RequestProc(PluginNumber, RT_MsgYesNo, title.c_str(), message.c_str(), nullptr, 0) != FALSE;
    } else {
        auto wmsg = MbToWide(message), wtitle = MbToWide(title);
        return MessageBoxW(parent_, wmsg.c_str(), wtitle.c_str(), MB_YESNO | MB_ICONQUESTION) == IDYES;
    }
}

bool WindowsUserFeedback::RequestText(const std::string& title, const std::string& prompt, std::string& returnedText, bool isPassword) {
    int type = isPassword ? RT_Password : RT_UserName;

    if (RequestProcW) {
        auto wtitle = MbToWide(title), wprompt = MbToWide(prompt);
        std::array<WCHAR, 1024> wbuf{};
        if (RequestProcW(PluginNumber, type, wtitle.c_str(), wprompt.c_str(), wbuf.data(), static_cast<int>(wbuf.size() - 1))) {
            const int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), -1, nullptr, 0, nullptr, nullptr);
            if (utf8Len > 0) {
                returnedText.assign(static_cast<size_t>(utf8Len - 1), '\0');
                WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), -1, returnedText.data(), utf8Len, nullptr, nullptr);
                return true;
            }
            std::array<char, 1024> fallback{};
            WideCharToMultiByte(CP_ACP, 0, wbuf.data(), -1, fallback.data(), static_cast<int>(fallback.size() - 1), nullptr, nullptr);
            returnedText = fallback.data();
            return true;
        }
    } else if (RequestProc) {
        std::array<char, 1024> buf{};
        if (RequestProc(PluginNumber, type, title.c_str(), prompt.c_str(), buf.data(), static_cast<int>(buf.size() - 1))) {
            returnedText = buf.data();
            return true;
        }
    }
    return false;
}
