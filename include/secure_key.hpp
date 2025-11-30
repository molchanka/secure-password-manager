#pragma once
#include <sodium.h>
#include <stdexcept>
#include <cstddef>

class SecureKey {
public:
    explicit SecureKey(size_t size)
        : size_(size)
    {
        ptr_ = static_cast<unsigned char*>(sodium_malloc(size_));
        if (!ptr_) {
            throw std::runtime_error("SecureKey: sodium_malloc failed");
        }

        if (sodium_mlock(ptr_, size_) != 0) {
            sodium_free(ptr_);
            throw std::runtime_error("SecureKey: sodium_mlock failed");
        }

        sodium_mprotect_readwrite(ptr_);
        sodium_memzero(ptr_, size_);
    }

    // non-copyable
    SecureKey(const SecureKey&) = delete;
    SecureKey& operator=(const SecureKey&) = delete;

    SecureKey(SecureKey&& other) noexcept
        : ptr_(other.ptr_), size_(other.size_)
    {
        other.ptr_ = nullptr;
        other.size_ = 0;
    }
    SecureKey& operator=(SecureKey&& other) noexcept {
        if (this != &other) {
            cleanup();
            ptr_ = other.ptr_;
            size_ = other.size_;
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    ~SecureKey() {
        cleanup();
    }

    unsigned char* data() { return ptr_; }
    const unsigned char* data() const { return ptr_; }
    size_t size() const { return size_; }

    void protect_noaccess() { sodium_mprotect_noaccess(ptr_); }
    void protect_readonly() { sodium_mprotect_readonly(ptr_); }
    void protect_readwrite() { sodium_mprotect_readwrite(ptr_); }

private:
    unsigned char* ptr_ = nullptr;
    size_t size_ = 0;

    void cleanup() {
        if (ptr_) {
            sodium_mprotect_readwrite(ptr_);
            sodium_memzero(ptr_, size_);
            sodium_munlock(ptr_, size_);
            sodium_free(ptr_);
        }
    }
};
