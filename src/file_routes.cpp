// src/file_routes.cpp
#include "file_routes.hpp"
#include "logger.hpp"
#include "nlohmann/json.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <vector>
#include <string>

using json = nlohmann::json;

namespace FileRoutes {
static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(const std::string& input) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    const unsigned char* bytes_to_encode = reinterpret_cast<const unsigned char*>(input.c_str());
    size_t in_len = input.length();

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::string base64_decode(const std::string& encoded_string) {
    size_t in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]) & 0xff;

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = 0; j < i; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]) & 0xff;

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

FileRouteHandler::FileRouteHandler(FileManager::UserFileManager* file_manager, 
                                 Auth::AuthManager* auth_manager, 
                                 Logger* logger)
    : file_manager_(file_manager), auth_manager_(auth_manager), logger_(logger) {
    logger_->log(LogLevel::DEBUG, ">>> Entering FileRouteHandler constructor");
    logger_->log(LogLevel::DEBUG, "<<< Exiting FileRouteHandler constructor");
}

HttpResponse FileRouteHandler::handleRequest(const std::string& method, 
                                           const std::string& path,
                                           const std::string& headers, 
                                           const std::string& body,
                                           const Auth::SessionInfo& session) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleRequest() - method: " + method + 
                ", path: " + path + ", user: " + session.username);
    
    // Remove /files prefix from path
    std::string file_path = path;
    if (file_path.find("/files") == 0) {
        file_path = file_path.substr(6);
    }
    
    HttpResponse response;
    
    try {
        if (file_path == "" || file_path == "/") {
            // Serve file manager page
            response = serveFileManagerPage(session);
        } else if (file_path == "/api/list" && method == "GET") {
            response = handleListFiles(session, "");
        } else if (file_path.find("/api/list/") == 0 && method == "GET") {
            std::string list_path = file_path.substr(10); // Remove "/api/list/"
            response = handleListFiles(session, list_path);
        } else if (file_path == "/api/upload" && method == "POST") {
            response = handleUploadFile(session, body);
        } else if (file_path.find("/api/download/") == 0 && method == "GET") {
            std::string download_path = file_path.substr(14); // Remove "/api/download/"
            response = handleDownloadFile(session, download_path);
        } else if (file_path.find("/api/delete") == 0 && method == "DELETE") {
            // Extract filepath from body or query params
            json request = json::parse(body);
            std::string filepath = request.value("path", "");
            response = handleDeleteFile(session, filepath);
        } else if (file_path == "/api/create-folder" && method == "POST") {
            response = handleCreateFolder(session, body);
        } else if (file_path == "/api/delete-folder" && method == "DELETE") {
            response = handleDeleteFolder(session, body);
        } else if (file_path == "/api/storage-info" && method == "GET") {
            response = handleGetStorageInfo(session);
        } else {
            response.status_code = 404;
            response.headers["Content-Type"] = "application/json";
            json error;
            error["error"] = "Not found";
            response.body = error.dump();
        }
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "File route error: " + std::string(e.what()));
        response.status_code = 500;
        response.headers["Content-Type"] = "application/json";
        json error;
        error["error"] = "Internal server error";
        response.body = error.dump();
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleRequest() - status: " + 
                std::to_string(response.status_code));
    return response;
}

HttpResponse FileRouteHandler::handleListFiles(const Auth::SessionInfo& session, 
                                              const std::string& path) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleListFiles() - path: " + path);
    
    HttpResponse response;
    
    auto files = file_manager_->listFiles(session.user_id, path);
    
    json result;
    result["success"] = true;
    result["path"] = path;
    result["files"] = json::array();
    
    for (const auto& file : files) {
        json file_json;
        file_json["name"] = file.name;
        file_json["type"] = file.type;
        file_json["size"] = file.size;
        file_json["modified"] = file.modified;
        file_json["permissions"] = file.permissions;
        result["files"].push_back(file_json);
    }
    
    response.status_code = 200;
    response.headers["Content-Type"] = "application/json";
    response.body = result.dump();
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleListFiles()");
    return response;
}

HttpResponse FileRouteHandler::handleUploadFile(const Auth::SessionInfo& session, 
                                               const std::string& body) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleUploadFile()");
    
    HttpResponse response;
    
    try {
        // Parse JSON request
        json request = json::parse(body);
        std::string filename = request.value("filename", "");
        std::string content = request.value("content", "");
        std::string path = request.value("path", "");
        bool is_base64 = request.value("base64", true);  // Default to base64 for compatibility
        
        if (filename.empty() || content.empty()) {
            response.status_code = 400;
            response.headers["Content-Type"] = "application/json";
            json error;
            error["success"] = false;
            error["message"] = "Missing filename or content";
            response.body = error.dump();
            logger_->log(LogLevel::DEBUG, "<<< Exiting handleUploadFile() - missing params");
            return response;
        }
        
        std::string file_content;
        
        if (is_base64) {
            // Decode base64 content
            logger_->log(LogLevel::DEBUG, "Decoding base64 content for file: " + filename);
            file_content = base64_decode(content);
            
            if (file_content.empty() && !content.empty()) {
                response.status_code = 400;
                response.headers["Content-Type"] = "application/json";
                json error;
                error["success"] = false;
                error["message"] = "Failed to decode base64 content";
                response.body = error.dump();
                logger_->log(LogLevel::DEBUG, "<<< Exiting handleUploadFile() - base64 decode failed");
                return response;
            }
        } else {
            // Use content as-is
            file_content = content;
        }
        
        logger_->log(LogLevel::DEBUG, "Original content size: " + std::to_string(content.size()) + 
                    ", Decoded size: " + std::to_string(file_content.size()));
        
        auto result = file_manager_->uploadFile(session.user_id, filename, file_content, path);
        
        json json_result;
        json_result["success"] = result.success;
        json_result["message"] = result.message;
        if (result.success) {
            json_result["filename"] = result.filename;
            json_result["size"] = result.size;
        }
        
        response.status_code = result.success ? 200 : 400;
        response.headers["Content-Type"] = "application/json";
        response.body = json_result.dump();
        
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "Upload exception: " + std::string(e.what()));
        response.status_code = 400;
        response.headers["Content-Type"] = "application/json";
        json error;
        error["success"] = false;
        error["message"] = "Invalid request: " + std::string(e.what());
        response.body = error.dump();
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleUploadFile()");
    return response;
}

HttpResponse FileRouteHandler::handleDownloadFile(const Auth::SessionInfo& session, 
                                                 const std::string& filepath) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleDownloadFile() - filepath: " + filepath);
    
    HttpResponse response;
    
    auto [success, content] = file_manager_->downloadFile(session.user_id, filepath);
    
    if (success) {
        response.status_code = 200;
        
        // Set appropriate content type
        std::string mime_type = getMimeType(filepath);
        response.headers["Content-Type"] = mime_type;
        
        // Force download for certain file types
        response.headers["Content-Disposition"] = "attachment; filename=\"" + 
                                                 fs::path(filepath).filename().string() + "\"";
        
        // Set content length
        response.headers["Content-Length"] = std::to_string(content.size());
        
        // Allow byte range requests
        response.headers["Accept-Ranges"] = "bytes";
        
        // Cache control
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
        
        response.body = content;
        
        logger_->log(LogLevel::INFO, "File download: " + filepath + " (" + 
                    std::to_string(content.size()) + " bytes)");
    } else {
        response.status_code = 404;
        response.headers["Content-Type"] = "application/json";
        json error;
        error["success"] = false;
        error["message"] = "File not found";
        response.body = error.dump();
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleDownloadFile()");
    return response;
}

HttpResponse FileRouteHandler::handleDeleteFile(const Auth::SessionInfo& session, 
                                               const std::string& filepath) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleDeleteFile() - filepath: " + filepath);
    
    HttpResponse response;
    
    bool success = file_manager_->deleteFile(session.user_id, filepath);
    
    json result;
    result["success"] = success;
    result["message"] = success ? "File deleted successfully" : "Failed to delete file";
    
    response.status_code = success ? 200 : 400;
    response.headers["Content-Type"] = "application/json";
    response.body = result.dump();
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleDeleteFile()");
    return response;
}

HttpResponse FileRouteHandler::handleCreateFolder(const Auth::SessionInfo& session, 
                                                 const std::string& body) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleCreateFolder()");
    
    HttpResponse response;
    
    try {
        json request = json::parse(body);
        std::string folder_name = request.value("name", "");
        std::string path = request.value("path", "");
        
        if (folder_name.empty()) {
            response.status_code = 400;
            response.headers["Content-Type"] = "application/json";
            json error;
            error["success"] = false;
            error["message"] = "Folder name is required";
            response.body = error.dump();
            logger_->log(LogLevel::DEBUG, "<<< Exiting handleCreateFolder() - missing name");
            return response;
        }
        
        bool success = file_manager_->createFolder(session.user_id, folder_name, path);
        
        json result;
        result["success"] = success;
        result["message"] = success ? "Folder created successfully" : "Failed to create folder";
        
        response.status_code = success ? 200 : 400;
        response.headers["Content-Type"] = "application/json";
        response.body = result.dump();
        
    } catch (const std::exception& e) {
        response.status_code = 400;
        response.headers["Content-Type"] = "application/json";
        json error;
        error["success"] = false;
        error["message"] = "Invalid request";
        response.body = error.dump();
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleCreateFolder()");
    return response;
}

HttpResponse FileRouteHandler::handleDeleteFolder(const Auth::SessionInfo& session, 
                                                 const std::string& body) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleDeleteFolder()");
    
    HttpResponse response;
    
    try {
        json request = json::parse(body);
        std::string folder_path = request.value("path", "");
        
        if (folder_path.empty()) {
            response.status_code = 400;
            response.headers["Content-Type"] = "application/json";
            json error;
            error["success"] = false;
            error["message"] = "Folder path is required";
            response.body = error.dump();
            logger_->log(LogLevel::DEBUG, "<<< Exiting handleDeleteFolder() - missing path");
            return response;
        }
        
        bool success = file_manager_->deleteFolder(session.user_id, folder_path);
        
        json result;
        result["success"] = success;
        result["message"] = success ? "Folder deleted successfully" : "Failed to delete folder";
        
        response.status_code = success ? 200 : 400;
        response.headers["Content-Type"] = "application/json";
        response.body = result.dump();
        
    } catch (const std::exception& e) {
        response.status_code = 400;
        response.headers["Content-Type"] = "application/json";
        json error;
        error["success"] = false;
        error["message"] = "Invalid request";
        response.body = error.dump();
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleDeleteFolder()");
    return response;
}

HttpResponse FileRouteHandler::handleGetStorageInfo(const Auth::SessionInfo& session) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleGetStorageInfo()");
    
    HttpResponse response;
    
    size_t used = file_manager_->getUserStorageUsed(session.user_id);
    size_t total = 1024 * 1024 * 1024; // 1GB
    
    json result;
    result["success"] = true;
    result["used"] = used;
    result["total"] = total;
    result["used_formatted"] = formatFileSize(used);
    result["total_formatted"] = formatFileSize(total);
    result["percentage"] = (used * 100.0) / total;
    
    response.status_code = 200;
    response.headers["Content-Type"] = "application/json";
    response.body = result.dump();
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleGetStorageInfo()");
    return response;
}

HttpResponse FileRouteHandler::serveFileManagerPage(const Auth::SessionInfo& session) {
    logger_->log(LogLevel::DEBUG, ">>> Entering serveFileManagerPage()");
    
    std::string html = R"html(
<!DOCTYPE html>
<html>
<head>
    <title>File Manager</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px;
            background: #f5f5f5;
        }
        .header { 
            background: #007bff; 
            color: white; 
            padding: 20px; 
            border-radius: 5px; 
            margin-bottom: 20px; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .toolbar {
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .btn {
            padding: 8px 16px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        .breadcrumb {
            padding: 10px;
            background: #e9ecef;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .breadcrumb a {
            color: #007bff;
            text-decoration: none;
            margin: 0 5px;
        }
        .file-list {
            width: 100%;
            border-collapse: collapse;
        }
        .file-list th, .file-list td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .file-list th {
            background: #f8f9fa;
            font-weight: bold;
        }
        .file-list tr:hover {
            background: #f5f5f5;
        }
        .file-icon {
            margin-right: 5px;
        }
        .file-actions {
            display: flex;
            gap: 5px;
        }
        .storage-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .storage-bar {
            width: 100%;
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        .storage-used {
            height: 100%;
            background: #007bff;
            transition: width 0.3s;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.4);
        }
        .modal-content {
            background-color: white;
            margin: 15% auto;
            padding: 20px;
            border: 1px solid #888;
            width: 400px;
            border-radius: 5px;
        }
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        .close:hover { color: black; }
        input[type="text"], input[type="file"] {
            width: 100%;
            padding: 8px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .drop-zone {
            border: 2px dashed #007bff;
            border-radius: 4px;
            padding: 40px;
            text-align: center;
            margin: 20px 0;
            background: #f8f9fa;
            cursor: pointer;
        }
        .drop-zone.dragover {
            background: #e3f2fd;
            border-color: #2196f3;
        }
        .checkbox-container {
            display: flex;
            align-items: center;
            margin-right: 10px;
        }
        .checkbox-container input[type="checkbox"] {
            margin-right: 5px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>File Manager - )html" + session.username + R"html(</h1>
        <a href="/dashboard" class="btn" style="background: white; color: #007bff;">Back to Dashboard</a>
    </div>
    
    <div class="container">
        <div class="storage-info">
            <h3>Storage Usage</h3>
            <div id="storageText">Loading...</div>
            <div class="storage-bar">
                <div class="storage-used" id="storageBar" style="width: 0%"></div>
            </div>
        </div>
        
        <div class="breadcrumb" id="breadcrumb">
            <a href="#" onclick="navigateTo('')">Home</a>
        </div>
        
        <div class="toolbar">
            <button class="btn btn-success" onclick="showUploadModal()">Upload File</button>
            <button class="btn" onclick="showCreateFolderModal()">New Folder</button>
            <button class="btn btn-danger" onclick="deleteSelected()" id="deleteBtn" style="display: none;">Delete Selected</button>
            <button class="btn" onclick="refreshFiles()">Refresh</button>
            <div class="checkbox-container">
                <input type="checkbox" id="selectAll" onchange="toggleSelectAll()">
                <label for="selectAll">Select All</label>
            </div>
        </div>
        
        <div class="drop-zone" id="dropZone">
            Drag and drop files here to upload
        </div>
        
        <table class="file-list">
            <thead>
                <tr>
                    <th width="30"></th>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Modified</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="fileList">
                <tr><td colspan="5" style="text-align: center;">Loading...</td></tr>
            </tbody>
        </table>
    </div>
    
    <!-- Upload Modal -->
    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeUploadModal()">&times;</span>
            <h2>Upload File</h2>
            <input type="file" id="fileInput" multiple>
            <div id="uploadProgress"></div>
            <button class="btn btn-success" onclick="uploadFiles()">Upload</button>
        </div>
    </div>
    
    <!-- Create Folder Modal -->
    <div id="folderModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeFolderModal()">&times;</span>
            <h2>Create New Folder</h2>
            <input type="text" id="folderName" placeholder="Folder name">
            <button class="btn btn-success" onclick="createFolder()">Create</button>
        </div>
    </div>
    
    <script>
    let currentPath = '';
    let selectedFiles = new Set();
    
    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
        loadFiles();
        loadStorageInfo();
        setupDragDrop();
    });
    
    // Storage info
    async function loadStorageInfo() {
        try {
            const response = await fetch('/files/api/storage-info');
            const data = await response.json();
            
            if (data.success) {
                document.getElementById('storageText').textContent = 
                    `${data.used_formatted} of ${data.total_formatted} used (${data.percentage.toFixed(1)}%)`;
                document.getElementById('storageBar').style.width = data.percentage + '%';
            }
        } catch (error) {
            console.error('Error loading storage info:', error);
        }
    }
    
    // File operations
    async function loadFiles(path = '') {
        currentPath = path;
        selectedFiles.clear();
        updateDeleteButton();
        
        try {
            const response = await fetch('/files/api/list' + (path ? '/' + path : ''));
            const data = await response.json();
            
            if (data.success) {
                updateBreadcrumb(path);
                displayFiles(data.files);
            }
        } catch (error) {
            console.error('Error loading files:', error);
            document.getElementById('fileList').innerHTML = 
                '<tr><td colspan="5" style="text-align: center; color: red;">Error loading files</td></tr>';
        }
    }
    
    function displayFiles(files) {
        const tbody = document.getElementById('fileList');
        
        if (files.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No files or folders</td></tr>';
            return;
        }
        
        tbody.innerHTML = files.map(file => {
            const icon = file.type === 'folder' ? '📁' : '📄';
            const size = file.type === 'folder' ? `${file.size} items` : formatFileSize(file.size);
            const checkbox = `<input type="checkbox" onchange="toggleSelection('${file.name}')" ${selectedFiles.has(file.name) ? 'checked' : ''}>`;
            
            return `
                <tr>
                    <td>${checkbox}</td>
                    <td>
                        ${file.type === 'folder' ? 
                            `<a href="#" onclick="navigateTo('${currentPath ? currentPath + '/' : ''}${file.name}')">${icon} ${file.name}</a>` :
                            `${icon} ${file.name}`
                        }
                    </td>
                    <td>${size}</td>
                    <td>${file.modified}</td>
                    <td class="file-actions">
                        ${file.type === 'file' ? 
                            `<button class="btn" onclick="downloadFile('${currentPath ? currentPath + '/' : ''}${file.name}')">Download</button>` :
                            ''
                        }
                        <button class="btn btn-danger" onclick="deleteItem('${file.name}', '${file.type}')">Delete</button>
                    </td>
                </tr>
            `;
        }).join('');
    }
    
    function updateBreadcrumb(path) {
        const parts = path ? path.split('/') : [];
        let html = '<a href="#" onclick="navigateTo(\'\')">Home</a>';
        let currentPath = '';
        
        for (const part of parts) {
            currentPath += (currentPath ? '/' : '') + part;
            html += ` / <a href="#" onclick="navigateTo('${currentPath}')">${part}</a>`;
        }
        
        document.getElementById('breadcrumb').innerHTML = html;
    }
    
    function navigateTo(path) {
        loadFiles(path);
    }
    
    function refreshFiles() {
        loadFiles(currentPath);
        loadStorageInfo();
    }
    
    // Selection handling
    function toggleSelection(filename) {
        if (selectedFiles.has(filename)) {
            selectedFiles.delete(filename);
        } else {
            selectedFiles.add(filename);
        }
        updateDeleteButton();
    }
    
    function toggleSelectAll() {
        const selectAll = document.getElementById('selectAll').checked;
        const checkboxes = document.querySelectorAll('#fileList input[type="checkbox"]');
        
        selectedFiles.clear();
        checkboxes.forEach(cb => {
            cb.checked = selectAll;
            if (selectAll) {
                // Extract filename from the onclick attribute
                const onclick = cb.getAttribute('onchange');
                const match = onclick.match(/toggleSelection\('(.+?)'\)/);
                if (match) {
                    selectedFiles.add(match[1]);
                }
            }
        });
        
        updateDeleteButton();
    }
    
    function updateDeleteButton() {
        const deleteBtn = document.getElementById('deleteBtn');
        if (selectedFiles.size > 0) {
            deleteBtn.style.display = 'inline-block';
            deleteBtn.textContent = `Delete Selected (${selectedFiles.size})`;
        } else {
            deleteBtn.style.display = 'none';
        }
    }
    
    // File upload
    function showUploadModal() {
        document.getElementById('uploadModal').style.display = 'block';
    }
    
    function closeUploadModal() {
        document.getElementById('uploadModal').style.display = 'none';
        document.getElementById('fileInput').value = '';
        document.getElementById('uploadProgress').innerHTML = '';
    }
    
    async function uploadFiles() {
        const fileInput = document.getElementById('fileInput');
        const files = fileInput.files;
        
        if (files.length === 0) {
            alert('Please select files to upload');
            return;
        }
        
        const progressDiv = document.getElementById('uploadProgress');
        progressDiv.innerHTML = '';
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            progressDiv.innerHTML += `<p>Uploading ${file.name}...</p>`;
            
            try {
                const content = await readFileAsBase64(file);
                const response = await fetch('/files/api/upload', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        filename: file.name,
                        content: content,
                        path: currentPath
                    })
                });
                
                const result = await response.json();
                if (result.success) {
                    progressDiv.innerHTML += `<p style="color: green;">✓ ${file.name} uploaded successfully</p>`;
                } else {
                    progressDiv.innerHTML += `<p style="color: red;">✗ ${file.name}: ${result.message}</p>`;
                }
            } catch (error) {
                progressDiv.innerHTML += `<p style="color: red;">✗ ${file.name}: Upload failed</p>`;
            }
        }
        
        setTimeout(() => {
            closeUploadModal();
            refreshFiles();
        }, 2000);
    }
    
    function readFileAsBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result.split(',')[1]);
            reader.onerror = reject;
            reader.readAsDataURL(file);
        });
    }
    
    // Drag and drop
    function setupDragDrop() {
        const dropZone = document.getElementById('dropZone');
        
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });
        
        dropZone.addEventListener('drop', async (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                document.getElementById('fileInput').files = files;
                showUploadModal();
            }
        });
    }
    
    // Download file
    async function downloadFile(filepath) {
        window.location.href = '/files/api/download/' + filepath;
    }
    
    // Delete operations
    async function deleteItem(name, type) {
        if (!confirm(`Are you sure you want to delete ${type} "${name}"?`)) {
            return;
        }
        
        try {
            const endpoint = type === 'folder' ? '/files/api/delete-folder' : '/files/api/delete';
            const response = await fetch(endpoint, {
                method: 'DELETE',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    path: currentPath ? currentPath + '/' + name : name
                })
            });
            
            const result = await response.json();
            if (result.success) {
                refreshFiles();
            } else {
                alert('Failed to delete: ' + result.message);
            }
        } catch (error) {
            alert('Error deleting item');
        }
    }
    
    async function deleteSelected() {
        if (selectedFiles.size === 0) return;
        
        if (!confirm(`Are you sure you want to delete ${selectedFiles.size} selected items?`)) {
            return;
        }
        
        let successCount = 0;
        for (const filename of selectedFiles) {
            // Determine if it's a file or folder (you might need to store this info)
            // For now, we'll try file deletion first
            try {
                const response = await fetch('/files/api/delete', {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        path: currentPath ? currentPath + '/' + filename : filename
                    })
                });
                
                const result = await response.json();
                if (result.success) {
                    successCount++;
                }
            } catch (error) {
                console.error('Error deleting:', filename);
            }
        }
        
        alert(`Deleted ${successCount} of ${selectedFiles.size} items`);
        refreshFiles();
    }
    
    // Create folder
    function showCreateFolderModal() {
        document.getElementById('folderModal').style.display = 'block';
        document.getElementById('folderName').focus();
    }
    
    function closeFolderModal() {
        document.getElementById('folderModal').style.display = 'none';
        document.getElementById('folderName').value = '';
    }
    
    async function createFolder() {
        const folderName = document.getElementById('folderName').value.trim();
        
        if (!folderName) {
            alert('Please enter a folder name');
            return;
        }
        
        try {
            const response = await fetch('/files/api/create-folder', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    name: folderName,
                    path: currentPath
                })
            });
            
            const result = await response.json();
            if (result.success) {
                closeFolderModal();
                refreshFiles();
            } else {
                alert('Failed to create folder: ' + result.message);
            }
        } catch (error) {
            alert('Error creating folder');
        }
    }
    
    // Utility functions
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Modal handling
    window.onclick = function(event) {
        if (event.target.className === 'modal') {
            event.target.style.display = 'none';
        }
    }
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeUploadModal();
            closeFolderModal();
        }
    });
    </script>
</body>
</html>
)html";
    
    HttpResponse response;
    response.status_code = 200;
    response.headers["Content-Type"] = "text/html";
    response.body = html;
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting serveFileManagerPage()");
    return response;
}

std::string FileRouteHandler::formatFileSize(size_t size) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double dsize = static_cast<double>(size);
    
    while (dsize >= 1024.0 && unit < 4) {
        dsize /= 1024.0;
        unit++;
    }
    
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << dsize << " " << units[unit];
    return ss.str();
}

std::string FileRouteHandler::getMimeType(const std::string& filename) {
    size_t dot_pos = filename.find_last_of('.');
    if (dot_pos == std::string::npos) {
        return "application/octet-stream";
    }
    
    std::string ext = filename.substr(dot_pos + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    static const std::map<std::string, std::string> mime_types = {
        {"txt", "text/plain"},
        {"html", "text/html"},
        {"css", "text/css"},
        {"js", "application/javascript"},
        {"json", "application/json"},
        {"xml", "application/xml"},
        {"pdf", "application/pdf"},
        {"zip", "application/zip"},
        {"jpg", "image/jpeg"},
        {"jpeg", "image/jpeg"},
        {"png", "image/png"},
        {"gif", "image/gif"},
        {"mp3", "audio/mpeg"},
        {"mp4", "video/mp4"},
        {"doc", "application/msword"},
        {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {"xls", "application/vnd.ms-excel"},
        {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
    };
    
    auto it = mime_types.find(ext);
    return (it != mime_types.end()) ? it->second : "application/octet-stream";
}

} // namespace FileRoutes