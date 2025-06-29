// src/user_file_manager.cpp
#include "user_file_manager.hpp"
#include <regex>
#include <ctime>

namespace FileManager {

UserFileManager::UserFileManager(const std::string& base_path, Logger* logger)
    : base_path_(base_path), logger_(logger) {
    logger_->log(LogLevel::DEBUG, ">>> Entering UserFileManager constructor - base_path: " + base_path);
    
    // Ensure base path exists
    if (!fs::exists(base_path_)) {
        fs::create_directories(base_path_);
        logger_->log(LogLevel::INFO, "Created base user storage directory: " + base_path_);
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting UserFileManager constructor");
}

bool UserFileManager::createUserFolder(int64_t user_id) {
    logger_->log(LogLevel::DEBUG, ">>> Entering createUserFolder() - user_id: " + std::to_string(user_id));
    
    try {
        std::string user_folder = getUserFolderPath(user_id);
        
        if (fs::exists(user_folder)) {
            logger_->log(LogLevel::WARNING, "User folder already exists: " + user_folder);
            logger_->log(LogLevel::DEBUG, "<<< Exiting createUserFolder() - already exists");
            return true;
        }
        
        fs::create_directories(user_folder);
        
        // Create default subdirectories
        fs::create_directories(user_folder + "/documents");
        fs::create_directories(user_folder + "/images");
        fs::create_directories(user_folder + "/downloads");
        
        // Create a welcome file
        std::ofstream welcome_file(user_folder + "/README.txt");
        if (welcome_file.is_open()) {
            welcome_file << "Welcome to your personal storage!\n\n";
            welcome_file << "You can upload, download, and manage your files here.\n";
            welcome_file << "Storage limit: 1GB\n";
            welcome_file << "Maximum file size: 100MB\n";
            welcome_file.close();
        }
        
        logger_->log(LogLevel::INFO, "Created user folder for user_id: " + std::to_string(user_id));
        logger_->log(LogLevel::DEBUG, "<<< Exiting createUserFolder() - success");
        return true;
        
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "Failed to create user folder: " + std::string(e.what()));
        logger_->log(LogLevel::DEBUG, "<<< Exiting createUserFolder() - exception");
        return false;
    }
}

bool UserFileManager::deleteUserFolder(int64_t user_id) {
    logger_->log(LogLevel::DEBUG, ">>> Entering deleteUserFolder() - user_id: " + std::to_string(user_id));
    
    try {
        std::string user_folder = getUserFolderPath(user_id);
        
        if (!fs::exists(user_folder)) {
            logger_->log(LogLevel::WARNING, "User folder does not exist: " + user_folder);
            logger_->log(LogLevel::DEBUG, "<<< Exiting deleteUserFolder() - not found");
            return true;
        }
        
        fs::remove_all(user_folder);
        logger_->log(LogLevel::INFO, "Deleted user folder for user_id: " + std::to_string(user_id));
        logger_->log(LogLevel::DEBUG, "<<< Exiting deleteUserFolder() - success");
        return true;
        
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "Failed to delete user folder: " + std::string(e.what()));
        logger_->log(LogLevel::DEBUG, "<<< Exiting deleteUserFolder() - exception");
        return false;
    }
}

std::string UserFileManager::getUserFolderPath(int64_t user_id) {
    return base_path_ + "/user_" + std::to_string(user_id);
}

std::vector<FileInfo> UserFileManager::listFiles(int64_t user_id, const std::string& relative_path) {
    logger_->log(LogLevel::DEBUG, ">>> Entering listFiles() - user_id: " + std::to_string(user_id) + 
                ", relative_path: " + relative_path);
    
    std::vector<FileInfo> files;
    
    try {
        std::string user_folder = getUserFolderPath(user_id);
        std::string target_path = user_folder;
        
        if (!relative_path.empty()) {
            if (!isPathSafe(relative_path)) {
                logger_->log(LogLevel::WARNING, "Unsafe path attempted: " + relative_path);
                logger_->log(LogLevel::DEBUG, "<<< Exiting listFiles() - unsafe path");
                return files;
            }
            target_path += "/" + relative_path;
        }
        
        if (!fs::exists(target_path) || !fs::is_directory(target_path)) {
            logger_->log(LogLevel::WARNING, "Directory does not exist: " + target_path);
            logger_->log(LogLevel::DEBUG, "<<< Exiting listFiles() - directory not found");
            return files;
        }
        
        for (const auto& entry : fs::directory_iterator(target_path)) {
            FileInfo info;
            info.name = entry.path().filename().string();
            
            if (fs::is_directory(entry)) {
                info.type = "folder";
                info.size = 0;
                // Count items in folder
                size_t item_count = 0;
                for (const auto& sub : fs::directory_iterator(entry)) {
                    item_count++;
                }
                info.size = item_count; // Store item count as size for folders
            } else {
                info.type = "file";
                info.size = fs::file_size(entry);
            }
            
            info.modified = formatFileTime(fs::last_write_time(entry));
            info.permissions = getFilePermissions(entry);
            
            files.push_back(info);
        }
        
        // Sort files: folders first, then by name
        std::sort(files.begin(), files.end(), [](const FileInfo& a, const FileInfo& b) {
            if (a.type != b.type) {
                return a.type == "folder";
            }
            return a.name < b.name;
        });
        
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "Error listing files: " + std::string(e.what()));
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting listFiles() - found " + std::to_string(files.size()) + " items");
    return files;
}

UploadResult UserFileManager::uploadFile(int64_t user_id, const std::string& filename, 
                                       const std::string& content, const std::string& relative_path) {
    logger_->log(LogLevel::DEBUG, ">>> Entering uploadFile() - user_id: " + std::to_string(user_id) + 
                ", filename: " + filename + ", content_size: " + std::to_string(content.size()));
    
    UploadResult result = {false, "", "", 0};
    
    try {
        // Check file size
        if (content.size() > MAX_FILE_SIZE) {
            result.message = "File too large. Maximum size is 100MB.";
            logger_->log(LogLevel::DEBUG, "<<< Exiting uploadFile() - file too large");
            return result;
        }
        
        // Check user storage quota
        size_t current_usage = getUserStorageUsed(user_id);
        if (current_usage + content.size() > MAX_USER_STORAGE) {
            result.message = "Storage quota exceeded. Maximum storage is 1GB.";
            logger_->log(LogLevel::DEBUG, "<<< Exiting uploadFile() - quota exceeded");
            return result;
        }
        
        // Sanitize filename
        std::string safe_filename = sanitizeFilename(filename);
        if (safe_filename.empty()) {
            result.message = "Invalid filename.";
            logger_->log(LogLevel::DEBUG, "<<< Exiting uploadFile() - invalid filename");
            return result;
        }
        
        // Build target path
        std::string user_folder = getUserFolderPath(user_id);
        std::string target_dir = user_folder;
        
        if (!relative_path.empty()) {
            if (!isPathSafe(relative_path)) {
                result.message = "Invalid upload path.";
                logger_->log(LogLevel::DEBUG, "<<< Exiting uploadFile() - unsafe path");
                return result;
            }
            target_dir += "/" + relative_path;
        }
        
        if (!fs::exists(target_dir)) {
            fs::create_directories(target_dir);
        }
        
        std::string full_path = target_dir + "/" + safe_filename;
        
        // Handle filename conflicts
        if (fs::exists(full_path)) {
            // Add timestamp to filename
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&time_t), "_%Y%m%d_%H%M%S");
            
            size_t dot_pos = safe_filename.find_last_of('.');
            if (dot_pos != std::string::npos) {
                safe_filename = safe_filename.substr(0, dot_pos) + ss.str() + 
                               safe_filename.substr(dot_pos);
            } else {
                safe_filename += ss.str();
            }
            
            full_path = target_dir + "/" + safe_filename;
        }
        
        // Write file
        std::ofstream file(full_path, std::ios::binary);
        if (!file.is_open()) {
            result.message = "Failed to create file.";
            logger_->log(LogLevel::DEBUG, "<<< Exiting uploadFile() - cannot create file");
            return result;
        }
        
        file.write(content.data(), content.size());
        file.close();
        
        result.success = true;
        result.message = "File uploaded successfully.";
        result.filename = safe_filename;
        result.size = content.size();
        
        logger_->log(LogLevel::INFO, "File uploaded: " + full_path + " (" + 
                    std::to_string(content.size()) + " bytes)");
        logger_->log(LogLevel::DEBUG, "<<< Exiting uploadFile() - success");
        
    } catch (const std::exception& e) {
        result.message = "Upload failed: " + std::string(e.what());
        logger_->log(LogLevel::ERROR, "Upload exception: " + std::string(e.what()));
        logger_->log(LogLevel::DEBUG, "<<< Exiting uploadFile() - exception");
    }
    
    return result;
}

std::pair<bool, std::string> UserFileManager::downloadFile(int64_t user_id, const std::string& filepath) {
    logger_->log(LogLevel::DEBUG, ">>> Entering downloadFile() - user_id: " + std::to_string(user_id) + 
                ", filepath: " + filepath);
    
    try {
        if (!isPathSafe(filepath)) {
            logger_->log(LogLevel::WARNING, "Unsafe download path attempted: " + filepath);
            logger_->log(LogLevel::DEBUG, "<<< Exiting downloadFile() - unsafe path");
            return {false, ""};
        }
        
        std::string user_folder = getUserFolderPath(user_id);
        std::string full_path = user_folder + "/" + filepath;
        
        if (!fs::exists(full_path) || !fs::is_regular_file(full_path)) {
            logger_->log(LogLevel::WARNING, "File not found: " + full_path);
            logger_->log(LogLevel::DEBUG, "<<< Exiting downloadFile() - file not found");
            return {false, ""};
        }
        
        // Read file content
        std::ifstream file(full_path, std::ios::binary);
        if (!file.is_open()) {
            logger_->log(LogLevel::ERROR, "Cannot open file: " + full_path);
            logger_->log(LogLevel::DEBUG, "<<< Exiting downloadFile() - cannot open");
            return {false, ""};
        }
        
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();
        
        logger_->log(LogLevel::INFO, "File downloaded: " + full_path + " (" + 
                    std::to_string(content.size()) + " bytes)");
        logger_->log(LogLevel::DEBUG, "<<< Exiting downloadFile() - success");
        return {true, content};
        
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "Download exception: " + std::string(e.what()));
        logger_->log(LogLevel::DEBUG, "<<< Exiting downloadFile() - exception");
        return {false, ""};
    }
}

bool UserFileManager::deleteFile(int64_t user_id, const std::string& filepath) {
    logger_->log(LogLevel::DEBUG, ">>> Entering deleteFile() - user_id: " + std::to_string(user_id) + 
                ", filepath: " + filepath);
    
    try {
        if (!isPathSafe(filepath)) {
            logger_->log(LogLevel::WARNING, "Unsafe delete path attempted: " + filepath);
            logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFile() - unsafe path");
            return false;
        }
        
        std::string user_folder = getUserFolderPath(user_id);
        std::string full_path = user_folder + "/" + filepath;
        
        if (!fs::exists(full_path)) {
            logger_->log(LogLevel::WARNING, "File not found: " + full_path);
            logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFile() - not found");
            return true; // Consider non-existent file as successfully deleted
        }
        
        if (!fs::is_regular_file(full_path)) {
            logger_->log(LogLevel::WARNING, "Not a regular file: " + full_path);
            logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFile() - not a file");
            return false;
        }
        
        fs::remove(full_path);
        logger_->log(LogLevel::INFO, "File deleted: " + full_path);
        logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFile() - success");
        return true;
        
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "Delete exception: " + std::string(e.what()));
        logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFile() - exception");
        return false;
    }
}

bool UserFileManager::createFolder(int64_t user_id, const std::string& folder_name, 
                                  const std::string& relative_path) {
    logger_->log(LogLevel::DEBUG, ">>> Entering createFolder() - user_id: " + std::to_string(user_id) + 
                ", folder_name: " + folder_name);
    
    try {
        std::string safe_folder_name = sanitizeFilename(folder_name);
        if (safe_folder_name.empty()) {
            logger_->log(LogLevel::WARNING, "Invalid folder name: " + folder_name);
            logger_->log(LogLevel::DEBUG, "<<< Exiting createFolder() - invalid name");
            return false;
        }
        
        std::string user_folder = getUserFolderPath(user_id);
        std::string target_dir = user_folder;
        
        if (!relative_path.empty()) {
            if (!isPathSafe(relative_path)) {
                logger_->log(LogLevel::WARNING, "Unsafe path: " + relative_path);
                logger_->log(LogLevel::DEBUG, "<<< Exiting createFolder() - unsafe path");
                return false;
            }
            target_dir += "/" + relative_path;
        }
        
        std::string new_folder_path = target_dir + "/" + safe_folder_name;
        
        if (fs::exists(new_folder_path)) {
            logger_->log(LogLevel::WARNING, "Folder already exists: " + new_folder_path);
            logger_->log(LogLevel::DEBUG, "<<< Exiting createFolder() - already exists");
            return false;
        }
        
        fs::create_directories(new_folder_path);
        logger_->log(LogLevel::INFO, "Folder created: " + new_folder_path);
        logger_->log(LogLevel::DEBUG, "<<< Exiting createFolder() - success");
        return true;
        
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "Create folder exception: " + std::string(e.what()));
        logger_->log(LogLevel::DEBUG, "<<< Exiting createFolder() - exception");
        return false;
    }
}

bool UserFileManager::deleteFolder(int64_t user_id, const std::string& folder_path) {
    logger_->log(LogLevel::DEBUG, ">>> Entering deleteFolder() - user_id: " + std::to_string(user_id) + 
                ", folder_path: " + folder_path);
    
    try {
        if (!isPathSafe(folder_path)) {
            logger_->log(LogLevel::WARNING, "Unsafe delete path attempted: " + folder_path);
            logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFolder() - unsafe path");
            return false;
        }
        
        // Prevent deletion of root user folder
        if (folder_path.empty() || folder_path == "/" || folder_path == ".") {
            logger_->log(LogLevel::WARNING, "Cannot delete root user folder");
            logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFolder() - root folder");
            return false;
        }
        
        std::string user_folder = getUserFolderPath(user_id);
        std::string full_path = user_folder + "/" + folder_path;
        
        if (!fs::exists(full_path)) {
            logger_->log(LogLevel::WARNING, "Folder not found: " + full_path);
            logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFolder() - not found");
            return true;
        }
        
        if (!fs::is_directory(full_path)) {
            logger_->log(LogLevel::WARNING, "Not a directory: " + full_path);
            logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFolder() - not a directory");
            return false;
        }
        
        fs::remove_all(full_path);
        logger_->log(LogLevel::INFO, "Folder deleted: " + full_path);
        logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFolder() - success");
        return true;
        
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "Delete folder exception: " + std::string(e.what()));
        logger_->log(LogLevel::DEBUG, "<<< Exiting deleteFolder() - exception");
        return false;
    }
}

bool UserFileManager::isPathSafe(const std::string& path) {
    // Check for path traversal attempts
    if (path.find("..") != std::string::npos) {
        return false;
    }
    
    // Check for absolute paths
    if (!path.empty() && (path[0] == '/' || path[0] == '\\')) {
        return false;
    }
    
    // Check for special characters that might cause issues
    if (path.find_first_of("<>:\"|?*") != std::string::npos) {
        return false;
    }
    
    return true;
}

std::string UserFileManager::sanitizeFilename(const std::string& filename) {
    if (filename.empty()) return "";
    
    std::string safe = filename;
    
    // Remove any path components
    size_t last_slash = safe.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        safe = safe.substr(last_slash + 1);
    }
    
    // Replace dangerous characters
    std::string illegal_chars = "<>:\"|?*";
    for (char& c : safe) {
        if (illegal_chars.find(c) != std::string::npos) {
            c = '_';
        }
        // Replace control characters
        if (c < 32) {
            c = '_';
        }
    }
    
    // Remove leading/trailing dots and spaces
    safe.erase(0, safe.find_first_not_of(". "));
    safe.erase(safe.find_last_not_of(". ") + 1);
    
    // Limit length
    if (safe.length() > 255) {
        safe = safe.substr(0, 255);
    }
    
    return safe;
}

size_t UserFileManager::getUserStorageUsed(int64_t user_id) {
    logger_->log(LogLevel::DEBUG, ">>> Entering getUserStorageUsed() - user_id: " + std::to_string(user_id));
    
    size_t total_size = 0;
    
    try {
        std::string user_folder = getUserFolderPath(user_id);
        
        if (!fs::exists(user_folder)) {
            logger_->log(LogLevel::DEBUG, "<<< Exiting getUserStorageUsed() - folder not found");
            return 0;
        }
        
        for (const auto& entry : fs::recursive_directory_iterator(user_folder)) {
            if (fs::is_regular_file(entry)) {
                total_size += fs::file_size(entry);
            }
        }
        
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "Error calculating storage: " + std::string(e.what()));
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting getUserStorageUsed() - size: " + std::to_string(total_size));
    return total_size;
}

std::string UserFileManager::formatFileTime(const fs::file_time_type& ftime) {
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
    );
    auto time_t = std::chrono::system_clock::to_time_t(sctp);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string UserFileManager::getFilePermissions(const fs::path& path) {
    try {
        auto perms = fs::status(path).permissions();
        std::string result;
        
        // Owner permissions
        result += (perms & fs::perms::owner_read) != fs::perms::none ? "r" : "-";
        result += (perms & fs::perms::owner_write) != fs::perms::none ? "w" : "-";
        result += (perms & fs::perms::owner_exec) != fs::perms::none ? "x" : "-";
        
        // Group permissions
        result += (perms & fs::perms::group_read) != fs::perms::none ? "r" : "-";
        result += (perms & fs::perms::group_write) != fs::perms::none ? "w" : "-";
        result += (perms & fs::perms::group_exec) != fs::perms::none ? "x" : "-";
        
        // Others permissions
        result += (perms & fs::perms::others_read) != fs::perms::none ? "r" : "-";
        result += (perms & fs::perms::others_write) != fs::perms::none ? "w" : "-";
        result += (perms & fs::perms::others_exec) != fs::perms::none ? "x" : "-";
        
        return result;
    } catch (...) {
        return "?????????";
    }
}

} // namespace FileManager