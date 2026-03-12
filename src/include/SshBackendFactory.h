#pragma once
// SshBackendFactory.h — Factory for creating the SSH backend.
// Today returns Libssh2Backend; future: could return WinCNG-native backend.

#include "ISshBackend.h"
#include "Libssh2Backend.h"
#include <memory>

inline std::unique_ptr<ISshBackend> CreateSshBackend()
{
    return std::make_unique<Libssh2Backend>();
}
