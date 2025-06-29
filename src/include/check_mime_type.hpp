#ifndef MIME_HPP
#define MIME_HPP
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <unordered_map>

// Useremo cpp-httplib (https://github.com/yhirose/cpp-httplib)
// È una libreria header-only, quindi basta includere httplib.h
#include "httplib.h"

// Per il parsing JSON useremo nlohmann/json (https://github.com/nlohmann/json)
#include "nlohmann/json.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

// Struttura per informazioni sui file
struct FileTypeInfo {
    std::string mime_type;
    bool is_binary;
    std::string default_folder;  // Sottocartella di default per questo tipo di file
};

// Classe per la gestione dei MIME types
class MimeTypeDetector {
private:
    // Declaration only - definition will be in the cpp file
    static const std::unordered_map<std::string, FileTypeInfo> mime_map;
    
    static std::string get_extension(const std::string& path) {
        size_t dot_pos = path.find_last_of('.');
        if (dot_pos == std::string::npos || dot_pos == path.length() - 1) {
            return "";
        }
        
        std::string ext = path.substr(dot_pos + 1);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        return ext;
    }
    
public:
    static std::string get_mime_type(const std::string& uri) {
        std::string clean_uri = uri;
        size_t query_pos = clean_uri.find('?');
        if (query_pos != std::string::npos) {
            clean_uri = clean_uri.substr(0, query_pos);
        }
        
        if (clean_uri.empty() || clean_uri == "/" || clean_uri.back() == '/') {
            return "text/html";
        }
        
        std::string ext = get_extension(clean_uri);
        auto it = mime_map.find(ext);
        if (it != mime_map.end()) {
            return it->second.mime_type;
        }
        
        return "application/octet-stream";
    }
    
    static bool is_binary(const std::string& uri) {
        std::string ext = get_extension(uri);
        auto it = mime_map.find(ext);
        if (it != mime_map.end()) {
            return it->second.is_binary;
        }
        return true;
    }
    
    static std::string get_default_folder(const std::string& uri) {
        std::string ext = get_extension(uri);
        auto it = mime_map.find(ext);
        if (it != mime_map.end()) {
            return it->second.default_folder;
        }
        return "";
    }
    
    // Funzione helper per trovare un file nelle possibili locazioni
    static std::string find_file(const std::string& requested_path, const std::string& web_root) {
        // Prima prova il percorso esatto richiesto
        std::string exact_path = web_root + requested_path;
        if (fs::exists(exact_path) && fs::is_regular_file(exact_path)) {
            return exact_path;
        }
        
        // Se non trovato, prova nella cartella di default per questo tipo di file
        std::string default_folder = get_default_folder(requested_path);
        if (!default_folder.empty()) {
            std::string filename = fs::path(requested_path).filename().string();
            std::string default_path = web_root + default_folder + filename;
            if (fs::exists(default_path) && fs::is_regular_file(default_path)) {
                return default_path;
            }
        }
        
        return "";  // File non trovato
    }
};

#endif