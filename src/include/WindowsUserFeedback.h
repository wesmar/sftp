#pragma once

#include "IUserFeedback.h"
#include <windows.h>

class WindowsUserFeedback : public IUserFeedback {
public:
    explicit WindowsUserFeedback(HWND parent = nullptr) : parent_(parent) {}

    void ShowError(const std::string& message, const std::string& title) override;
    void ShowMessage(const std::string& message, const std::string& title) override;
    bool AskYesNo(const std::string& message, const std::string& title) override;
    bool RequestText(const std::string& title, const std::string& prompt, std::string& returnedText, bool isPassword) override;

private:
    HWND parent_;
};
