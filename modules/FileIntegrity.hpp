#pragma once
#include <string>
#include <vector>

struct FileEntry {
    std::string path;
    std::string label;
    std::string description;
};

struct IntegrityResult {
    std::string path;
    std::string label;
    enum Status { OK, MODIFIED, MISSING, NO_BASELINE } status;
};

class FileIntegrity {
public:
    static std::vector<FileEntry> criticalFiles();
    static bool generateBaseline();
    static std::vector<IntegrityResult> check();
    static bool hasBaseline();
    static bool isServiceEnabled();
    static bool enableService();
    static bool disableService();
    static bool installServiceFile();
    static bool purge();

private:
    static std::string sha256file(const std::string& path);
    static bool        saveBaseline(const std::vector<std::pair<std::string,std::string>>& hashes);
    static std::vector<std::pair<std::string,std::string>> loadBaseline();

    static const std::string BASELINE_PATH;
    static const std::string SERVICE_FILE;
    static const std::string WANTS_LINK;
};
