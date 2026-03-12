#pragma once

#include <string>

/**
 * Interface for user interaction and feedback.
 * This decouples the business/network logic from specific UI implementations like Win32 MessageBox.
 */
class IUserFeedback {
public:
    virtual ~IUserFeedback() = default;

    /**
     * Shows an error message to the user.
     */
    virtual void ShowError(const std::string& message, const std::string& title = "SFTP Error") = 0;

    /**
     * Shows an informational message to the user.
     */
    virtual void ShowMessage(const std::string& message, const std::string& title = "SFTP") = 0;

    /**
     * Asks a Yes/No question to the user.
     * @return true if the user selected Yes, false otherwise.
     */
    virtual bool AskYesNo(const std::string& message, const std::string& title = "SFTP Question") = 0;

    /**
     * Requests text input from the user (e.g. password or username).
     * @return true if successful, false if cancelled.
     */
    virtual bool RequestText(const std::string& title, const std::string& prompt, std::string& returnedText, bool isPassword = false) = 0;
};
