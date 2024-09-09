#include "pch.h"
#include <random>

#include "random.h"

using namespace LunaAPI;

std::mt19937 rng(time(0));

void LunaAPI::RandomString(char* buffer, const char* options, size_t length) {
    size_t numOptions = strlen(options);
    for (size_t i = 0; i < length; i++) {
        buffer[i] = options[rng() % numOptions];
    }
}