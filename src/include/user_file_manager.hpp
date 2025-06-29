// src/user_file_manager.hpp
#ifndef USER_FILE_MANAGER_HPP
#define USER_FILE_MANAGER_HPP

#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include "logger.hpp"
#include "auth.hpp"

namespace fs = std::filesystem;

namespace FileManager {

// File information structure
struct FileInfo {
    std::string name;
    std::string type; // "file" or "folder"
    size_t size;
    std::string modified;
    std::string permissions;
};

// Upload result
struct UploadResult {
    bool success;
    std::string message;
    std::string filename;
    size_t size;
};

// File manager class
class UserFileManager {
public:
    UserFileManager(const std::string& base_path, Logger* logger);
    
    // User folder operations
    bool createUserFolder(int64_t user_id);
    bool deleteUserFolder(int64_t user_id);
    std::string getUserFolderPath(int64_t user_id);
    
    // File operations
    std::vector<FileInfo> listFiles(int64_t user_id, const std::string& relative_path = "");
    UploadResult uploadFile(int64_t user_id, const std::string& filename, 
                           const std::string& content, const std::string& relative_path = "");
    std::pair<bool, std::string> downloadFile(int64_t user_id, const std::string& filepath);
    bool deleteFile(int64_t user_id, const std::string& filepath);
    
    // Folder operations
    bool createFolder(int64_t user_id, const std::string& folder_name, const std::string& relative_path = "");
    bool deleteFolder(int64_t user_id, const std::string& folder_path);
    
    // Utility functions
    bool isPathSafe(const std::string& path);
    std::string sanitizeFilename(const std::string& filename);
    size_t getUserStorageUsed(int64_t user_id);
    
private:
    std::string base_path_;
    Logger* logger_;
    const size_t MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
    const size_t MAX_USER_STORAGE = 1024 * 1024 * 1024; // 1GB
    
    std::string formatFileTime(const fs::file_time_type& ftime);
    std::string getFilePermissions(const fs::path& path);
};

} // namespace FileManager

#endif // USER_FILE_MANAGER_HPP