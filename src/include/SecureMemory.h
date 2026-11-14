#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>

// Allocator that wipes every block it releases, including the old buffer a
// growing vector leaves behind, so secrets do not linger in freed heap memory.
template <class T>
struct ZeroingAllocator {
    using value_type = T;

    ZeroingAllocator() noexcept = default;
    template <class U> ZeroingAllocator(const ZeroingAllocator<U>&) noexcept {}

    T* allocate(std::size_t n)
    {
        if (n > static_cast<std::size_t>(-1) / sizeof(T))
            throw std::bad_array_new_length();
        return static_cast<T*>(::operator new(n * sizeof(T)));
    }

    void deallocate(T* p, std::size_t n) noexcept
    {
        SecureZeroMemory(p, n * sizeof(T));
        ::operator delete(p);
    }

    template <class U> bool operator==(const ZeroingAllocator<U>&) const noexcept { return true; }
};

// Byte containers for key material, passphrases and decrypted blobs. Vectors
// rather than strings: std::string keeps short values inline, where the
// allocator never sees (and so never wipes) them.
using SecureBytes = std::vector<uint8_t, ZeroingAllocator<uint8_t>>;
using SecureChars = std::vector<char, ZeroingAllocator<char>>;
