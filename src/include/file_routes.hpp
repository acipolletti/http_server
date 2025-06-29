// src/file_routes.hpp
#ifndef FILE_ROUTES_HPP
#define FILE_ROUTES_HPP

#include <string>
#include <map>
#include "user_file_manager.hpp"
#include "auth.hpp"

class Logger;

namespace FileRoutes {

// HTTP response structure
struct HttpResponse {
    int status_code;
    std::map<std::string, std::string> headers;
    std::string body;
};

// File routes handler
class FileRouteHandler {
public:
    FileRouteHandler(FileManager::UserFileManager* file_manager, 
                     Auth::AuthManager* auth_manager, 
                     Logger* logger);
    
    // Main request handler
    HttpResponse handleRequest(const std::string& method, 
                             const std::string& path,
                             const std::string& headers, 
                             const std::string& body,
                             const Auth::SessionInfo& session);

private:
    FileManager::UserFileManager* file_manager_;
    Auth::AuthManager* auth_manager_;
    Logger* logger_;
    
    // API endpoints
    HttpResponse handleListFiles(const Auth::SessionInfo& session, const std::string& path);
    HttpResponse handleUploadFile(const Auth::SessionInfo& session, const std::string& body);
    HttpResponse handleDownloadFile(const Auth::SessionInfo& session, const std::string& filepath);
    HttpResponse handleDeleteFile(const Auth::SessionInfo& session, const std::string& filepath);
    HttpResponse handleCreateFolder(const Auth::SessionInfo& session, const std::string& body);
    HttpResponse handleDeleteFolder(const Auth::SessionInfo& session, const std::string& body);
    HttpResponse handleGetStorageInfo(const Auth::SessionInfo& session);
    
    // File manager page
    HttpResponse serveFileManagerPage(const Auth::SessionInfo& session);
    
    // Utility functions
    std::string parseMultipartFormData(const std::string& body, const std::string& boundary,
                                      std::map<std::string, std::string>& fields,
                                      std::map<std::string, std::pair<std::string, std::string>>& files);
    std::string formatFileSize(size_t size);
    std::string getMimeType(const std::string& filename);
};

} // namespace FileRoutes

#endif // FILE_ROUTES_HPP