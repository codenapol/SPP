#pragma once
#include <string>
#include <vector>

class HostsBlocker {
public:
    enum Level { NONE = 0, MINIMUM = 1, BASIQUE = 2, HARD = 3 };

    static Level  currentLevel();
    static bool   apply(Level level);

    static std::string levelName(Level level);
    static std::string levelDescription(Level level);

private:
    static const std::string HOSTS_PATH;
    static const std::string MARKER_BEGIN;
    static const std::string MARKER_END;

    static std::vector<std::string> domainsFor(Level level);

    static std::vector<std::string> minimumDomains();
    static std::vector<std::string> basiqueDomains();
    static std::vector<std::string> hardDomains();
};
