#pragma once
#include <sodium.h>
#include <stdexcept>
#include <cstddef>
#include <cstring>

class SecureBuffer {
public:
    explicit SecureBuffer(size_t size)
        : size_(size)
    {
        ptr_ = static_cast<unsigned char*>(sodium_malloc(size_));
        if (!ptr_) {
            throw std::runtime_error("SecureBuffer: sodium_malloc failed");
        }

        if (sodium_mlock(ptr_, size_) != 0) {
            sodium_free(ptr_);
            throw std::runtime_error("SecureBuffer: sodium_mlock failed");
        }

        sodium_mprotect_readwrite(ptr_);
        sodium_memzero(ptr_, size_);
    }

    // Non-copyable
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Movable
    SecureBuffer(SecureBuffer&& other) noexcept
        : ptr_(other.ptr_), size_(other.size_)
    {
        other.ptr_ = nullptr;
        other.size_ = 0;
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            cleanup();
            ptr_ = other.ptr_;
            size_ = other.size_;
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    ~SecureBuffer() {
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
