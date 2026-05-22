#pragma once

struct CleanupResult {
    int ok   = 0;
    int fail = 0;
};

class Cleanup {
public:
    static CleanupResult removeAllTraces();
};
