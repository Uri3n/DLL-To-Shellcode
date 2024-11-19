#ifndef INCLUDE_HPP
#define INCLUDE_HPP
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <optional>
#include <filesystem>
#include <cstdint>

#ifdef _WIN64
    #include <Windows.h>
#endif

template<typename T> requires std::is_invocable_v<T>
class defer_wrapper {
    T callable;
public:
    auto call() -> decltype(callable()) {
        return callable();
    }

    explicit defer_wrapper(T func) : callable(func) {}
    ~defer_wrapper() { callable(); }
};

template<typename T>
defer_wrapper<T> defer(T callable) {
    return defer_wrapper<T>(callable);
}

#endif //INCLUDE_HPP
