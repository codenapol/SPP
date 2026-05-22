#pragma once
#include "Kernel.hpp"

class Optimization {
public:
    static std::vector<SysctlOption> memoryOptions();
    static std::vector<SysctlOption> networkOptions();
};
