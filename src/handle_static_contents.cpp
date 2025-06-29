#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>
#include <optional>
#include <chrono>
#include <iomanip>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <thread>
#include "logger.hpp"
#include "check_mime_type.hpp"

namespace fs = std::filesystem;

// Global logger pointer for this module
extern std::unique_ptr<Logger> logger;



// Helper macro for logging with fallback
#define LOG_DEBUG(msg) logger->log(LogLevel::DEBUG, msg)
#define LOG_INFO(msg) logger->log(LogLevel::INFO, msg)
#define LOG_WARNING(msg) logger->log(LogLevel::WARNING, msg)
#define LOG_ERROR(msg) logger->log(LogLevel::ERROR, msg)

struct HttpResponse {
    int status_code;
    std::map<std::string, std::string> headers;
    std::string body;
    bool is_chunked = false;
    std::string file_path_for_chunking;
    
    // Dimensione soglia per attivare chunked encoding (10MB)
    static constexpr size_t CHUNKED_THRESHOLD = 10 * 1024 * 1024;
    // Dimensione di ogni chunk (64KB)
    static constexpr size_t CHUNK_SIZE = 64 * 1024;
    
    // Metodo per ottenere gli headers
    const std::map<std::string, std::string>& getHeaders() const {
        return headers;
    }
    
    // Metodo per ottenere il body
    const std::string& getBody() const {
        return body;
    }
    
    // Metodo per verificare se la risposta è chunked
    bool isChunked() const {
        return is_chunked;
    }
    
    // Metodo per ottenere il percorso del file per chunking
    const std::string& getFilePathForChunking() const {
        return file_path_for_chunking;
    }
    
    // Metodo per generare gli headers HTTP
    std::string getHeadersString() const {
        LOG_DEBUG(">>> Entering HttpResponse::getHeadersString()");
        std::ostringstream response;
        
        // Status line
        response << "HTTP/1.1 " << status_code << " " << getStatusText() << "\r\n";
        
        // Headers
        for (const auto& [key, value] : headers) {
            response << key << ": " << value << "\r\n";
        }
        
        // Empty line between headers and body
        response << "\r\n";
        
        LOG_DEBUG("<<< Exiting HttpResponse::getHeadersString()");
        return response.str();
    }
    
    // Metodo per inviare una risposta chunked (da usare con un socket)
    template<typename SocketType>
    void sendChunkedResponse(SocketType& socket) const {
        LOG_DEBUG(">>> Entering HttpResponse::sendChunkedResponse()");
        
        // Prima invia gli headers
        std::string headers_str = getHeadersString();
        socket.send(headers_str.data(), headers_str.size());
        
        if (is_chunked && !file_path_for_chunking.empty()) {
            // Invia il file a chunk
            std::ifstream file(file_path_for_chunking, std::ios::binary);
            if (file) {
                std::vector<char> buffer(CHUNK_SIZE);
                
                while (file.good()) {
                    file.read(buffer.data(), CHUNK_SIZE);
                    std::streamsize bytes_read = file.gcount();
                    
                    if (bytes_read > 0) {
                        // Invia la dimensione del chunk in esadecimale
                        std::ostringstream chunk_size;
                        chunk_size << std::hex << bytes_read << "\r\n";
                        socket.send(chunk_size.str().data(), chunk_size.str().size());
                        
                        // Invia il chunk
                        socket.send(buffer.data(), bytes_read);
                        
                        // Invia CRLF dopo il chunk
                        socket.send("\r\n", 2);
                    }
                }
                
                // Invia il chunk finale (0\r\n\r\n)
                socket.send("0\r\n\r\n", 5);
            }
        } else {
            // Risposta normale non-chunked
            socket.send(body.data(), body.size());
        }
        
        LOG_DEBUG("<<< Exiting HttpResponse::sendChunkedResponse()");
    }
    
    std::string toString() const {
        LOG_DEBUG(">>> Entering HttpResponse::toString()");
        std::ostringstream response;
        
        response << getHeadersString();
        
        // Body (solo per risposte non-chunked)
        if (!is_chunked) {
            response << body;
        }
        
        LOG_DEBUG("<<< Exiting HttpResponse::toString()");
        return response.str();
    }
    
private:
    std::string getStatusText() const {
        switch (status_code) {
            case 200: return "OK";
            case 404: return "Not Found";
            case 500: return "Internal Server Error";
            default: return "Unknown";
        }
    }
};

// Funzione per ottenere il MIME type basato sull'estensione del file
std::string getMimeType(const fs::path& path) {
    LOG_DEBUG(">>> Entering getMimeType() - path: " + path.string());
    
    static const std::map<std::string, std::string> mime_types = {
        // Text files
        {".html", "text/html"},
        {".htm", "text/html"},
        {".css", "text/css"},
        {".txt", "text/plain"},
        {".csv", "text/csv"},
        {".xml", "text/xml"},
        
        // Application files
        {".js", "application/javascript"},
        {".json", "application/json"},
        {".pdf", "application/pdf"},
        {".zip", "application/zip"},
        {".rar", "application/x-rar-compressed"},
        {".7z", "application/x-7z-compressed"},
        {".doc", "application/msword"},
        {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {".xls", "application/vnd.ms-excel"},
        {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {".ppt", "application/vnd.ms-powerpoint"},
        {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        
        // Images
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".png", "image/png"},
        {".gif", "image/gif"},
        {".bmp", "image/bmp"},
        {".svg", "image/svg+xml"},
        {".webp", "image/webp"},
        {".ico", "image/x-icon"},
        {".tiff", "image/tiff"},
        {".tif", "image/tiff"},
        
        // Audio
        {".mp3", "audio/mpeg"},
        {".wav", "audio/wav"},
        {".ogg", "audio/ogg"},
        {".m4a", "audio/mp4"},
        {".flac", "audio/flac"},
        
        // Video
        {".mp4", "video/mp4"},
        {".avi", "video/x-msvideo"},
        {".mov", "video/quicktime"},
        {".wmv", "video/x-ms-wmv"},
        {".flv", "video/x-flv"},
        {".webm", "video/webm"},
        {".mkv", "video/x-matroska"},
        
        // Fonts
        {".ttf", "font/ttf"},
        {".otf", "font/otf"},
        {".woff", "font/woff"},
        {".woff2", "font/woff2"}
    };
    
    auto ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    auto it = mime_types.find(ext);
    std::string mime_type = (it != mime_types.end()) ? it->second : "application/octet-stream";
    
    LOG_DEBUG("<<< Exiting getMimeType() - mime_type: " + mime_type);
    return mime_type;
}

// Funzione per ottenere la data/ora corrente in formato HTTP
std::string getCurrentHttpDate() {
    LOG_DEBUG(">>> Entering getCurrentHttpDate()");
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm* gmt_time = std::gmtime(&time_t);
    
    std::ostringstream date_stream;
    date_stream << std::put_time(gmt_time, "%a, %d %b %Y %H:%M:%S GMT");
    
    std::string date = date_stream.str();
    LOG_DEBUG("<<< Exiting getCurrentHttpDate() - date: " + date);
    return date;
}

// Funzione deprecata per leggere file HTML - mantenuta per compatibilità
// NOTA: Si consiglia di usare handleFileRequest/load_file_advanced per tutti i tipi di file
std::optional<HttpResponse> generateHttpResponse(const std::string& file_path) {
    LOG_DEBUG(">>> Entering generateHttpResponse() - file_path: " + file_path);
    
    HttpResponse response;
    
    try {
        // Verifica che il file esista
        fs::path path(file_path);
        if (!fs::exists(path)) {
            LOG_WARNING("File not found: " + file_path);
            response.status_code = 404;
            response.headers["Content-Type"] = "text/html; charset=UTF-8";
            response.headers["Date"] = getCurrentHttpDate();
            response.body = R"(<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested file was not found.</p>
</body>
</html>)";
            LOG_DEBUG("<<< Exiting generateHttpResponse() - 404");
            return response;
        }
        
        // Verifica che sia un file regolare
        if (!fs::is_regular_file(path)) {
            LOG_ERROR("Path is not a regular file: " + file_path);
            response.status_code = 500;
            response.headers["Content-Type"] = "text/html; charset=UTF-8";
            response.headers["Date"] = getCurrentHttpDate();
            response.body = R"(<!DOCTYPE html>
<html>
<head>
    <title>500 Internal Server Error</title>
</head>
<body>
    <h1>500 Internal Server Error</h1>
    <p>The requested path is not a regular file.</p>
</body>
</html>)";
            LOG_DEBUG("<<< Exiting generateHttpResponse() - 500");
            return response;
        }
        
        // Leggi il contenuto del file
        LOG_DEBUG("Reading file content...");
        std::ifstream file(path, std::ios::in | std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file");
        }
        
        // Leggi tutto il contenuto in una stringa
        std::ostringstream content_stream;
        content_stream << file.rdbuf();
        std::string content = content_stream.str();
        
        // Costruisci la risposta HTTP di successo
        response.status_code = 200;
        response.body = content;
        
        // Imposta gli headers
        response.headers["Content-Type"] = getMimeType(path) + "; charset=UTF-8";
        response.headers["Content-Length"] = std::to_string(content.size());
        response.headers["Date"] = getCurrentHttpDate();
        response.headers["Server"] = "C++17 HTTP Server/1.0";
        response.headers["Cache-Control"] = "public, max-age=3600";
        
        // Aggiungi Last-Modified header
        auto ftime = fs::last_write_time(path);
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        auto time_t = std::chrono::system_clock::to_time_t(sctp);
        std::tm* gmt_time = std::gmtime(&time_t);
        std::ostringstream last_modified;
        last_modified << std::put_time(gmt_time, "%a, %d %b %Y %H:%M:%S GMT");
        response.headers["Last-Modified"] = last_modified.str();
        
        LOG_DEBUG("<<< Exiting generateHttpResponse() - 200");
        return response;
        
    } catch (const std::exception& e) {
        // Errore durante la lettura del file
        LOG_ERROR("Exception in generateHttpResponse: " + std::string(e.what()));
        response.status_code = 500;
        response.headers["Content-Type"] = "text/html; charset=UTF-8";
        response.headers["Date"] = getCurrentHttpDate();
        response.body = R"(<!DOCTYPE html>
<html>
<head>
    <title>500 Internal Server Error</title>
</head>
<body>
    <h1>500 Internal Server Error</h1>
    <p>An error occurred while reading the file.</p>
</body>
</html>)";
        LOG_DEBUG("<<< Exiting generateHttpResponse() - 500 (exception)");
        return response;
    }
}

// Struttura per contenere le informazioni dell'URI parsato
struct ParsedUri {
    std::string path;
    std::string filename;
    std::string extension;
    std::map<std::string, std::string> query_params;
    std::string subfolder;
};
// URL encoding utility function
std::string urlEncode(const std::string& value) {
    LOG_DEBUG(">>> Entering urlEncode() - str: " + value);
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
            escaped << c;
        } else {
            // Any other characters are percent-encoded
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char) c);
            escaped << std::nouppercase;
        }
    }
    LOG_DEBUG("<<< Exiting urlEncode() - result: " + escaped.str());
    return escaped.str();
}

// URL decoding utility function (also useful to have)
std::string urlDecode(const std::string& str) {
    LOG_DEBUG(">>> Entering urlDecode() - str: " + str);
    std::string result;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int hex_value;
            std::istringstream hex_stream(str.substr(i + 1, 2));
            if (hex_stream >> std::hex >> hex_value) {
                result += static_cast<char>(hex_value);
                i += 2;
            } else {
                result += str[i];
            }
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    LOG_DEBUG("<<< Exiting urlDecode() - result: " + result);
    return result;
}

// Funzione per fare il parsing dell'URI
std::optional<ParsedUri> parseUri(const std::string& uri) {
    LOG_DEBUG(">>> Entering parseUri() - uri: " + uri);
    
    ParsedUri parsed;
    
    // Trova la posizione del '?' per separare path e query string
    size_t query_pos = uri.find('?');
    std::string path_part = (query_pos != std::string::npos) ? uri.substr(0, query_pos) : uri;
    std::string query_part = (query_pos != std::string::npos) ? uri.substr(query_pos + 1) : "";
    
    // Decodifica il path
    parsed.path = urlDecode(path_part);
    
    // Rimuovi eventuali ".." per sicurezza (path traversal attack)
    if (parsed.path.find("..") != std::string::npos) {
        LOG_WARNING("Path traversal attempt detected: " + uri);
        LOG_DEBUG("<<< Exiting parseUri() - security violation");
        return std::nullopt; // URI non valido per sicurezza
    }
    
    // Estrai filename e estensione
    fs::path path_obj(parsed.path);
    parsed.filename = path_obj.filename().string();
    parsed.extension = path_obj.extension().string();
    
    // Converti estensione in minuscolo
    std::transform(parsed.extension.begin(), parsed.extension.end(), 
                   parsed.extension.begin(), ::tolower);
    
    // Parsing dei parametri query (se presenti)
    if (!query_part.empty()) {
        std::istringstream query_stream(query_part);
        std::string param;
        while (std::getline(query_stream, param, '&')) {
            size_t eq_pos = param.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = urlDecode(param.substr(0, eq_pos));
                std::string value = urlDecode(param.substr(eq_pos + 1));
                parsed.query_params[key] = value;
            }
        }
    }
    
    LOG_DEBUG("<<< Exiting parseUri() - path: " + parsed.path + ", filename: " + parsed.filename);
    return parsed;
}

// Funzione principale per gestire richieste di file generici (incluso HTML)
std::optional<HttpResponse> handleFileRequest(const std::string& uri, const std::string& document_root = ".") {
    LOG_DEBUG(">>> Entering handleFileRequest() - uri: " + uri + ", document_root: " + document_root);
    
    HttpResponse response;
    
    // Parsing dell'URI
    auto parsed_opt = parseUri(uri);
    if (!parsed_opt) {
        LOG_WARNING("Invalid URI format: " + uri);
        response.status_code = 400;
        response.headers["Content-Type"] = "text/html; charset=UTF-8";
        response.headers["Date"] = getCurrentHttpDate();
        response.body = R"(<!DOCTYPE html>
<html>
<head>
    <title>400 Bad Request</title>
</head>
<body>
    <h1>400 Bad Request</h1>
    <p>Invalid URI format.</p>
</body>
</html>)";
        LOG_DEBUG("<<< Exiting handleFileRequest() - 400");
        return response;
    }
    
    ParsedUri parsed = parsed_opt.value();
    std::string folder=MimeTypeDetector::get_default_folder(uri);

    try {
        // Costruisci il percorso completo del file
        // Rimuovi lo slash iniziale se presente
        std::string relative_path = parsed.path;
        if (!relative_path.empty() && relative_path[0] == '/') {
            relative_path = relative_path.substr(1);
        }
        
        fs::path file_path = fs::path(document_root+folder) / parsed.filename;
        LOG_DEBUG("Attempting to access file: " + file_path.string());
        
        // Normalizza il percorso e verifica che sia all'interno del document_root
        fs::path normalized_path = fs::canonical(file_path);
        fs::path normalized_root = fs::canonical(document_root);
        
        // Sicurezza: verifica che il file sia all'interno del document_root
        if (normalized_path.string().find(normalized_root.string()) != 0) {
            LOG_WARNING("Access denied - file outside document root: " + normalized_path.string());
            response.status_code = 403;
            response.headers["Content-Type"] = "text/html; charset=UTF-8";
            response.headers["Date"] = getCurrentHttpDate();
            response.body = R"(<!DOCTYPE html>
<html>
<head>
    <title>403 Forbidden</title>
</head>
<body>
    <h1>403 Forbidden</h1>
    <p>Access denied.</p>
</body>
</html>)";
            LOG_DEBUG("<<< Exiting handleFileRequest() - 403");
            return response;
        }
        
        // Verifica che il file esista
        if (!fs::exists(normalized_path) || !fs::is_regular_file(normalized_path)) {
            LOG_INFO("File not found: " + normalized_path.string());
            response.status_code = 404;
            response.headers["Content-Type"] = "text/html; charset=UTF-8";
            response.headers["Date"] = getCurrentHttpDate();
            response.body = R"(<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested file was not found.</p>
</body>
</html>)";
            LOG_DEBUG("<<< Exiting handleFileRequest() - 404");
            return response;
        }
        
        // Ottieni la dimensione del file
        std::streamsize file_size = fs::file_size(normalized_path);
        LOG_DEBUG("File size: " + std::to_string(file_size) + " bytes");
        
        // Imposta la risposta di successo
        response.status_code = 200;
        
        // Imposta gli headers appropriati per il file
        std::string mime_type = getMimeType(normalized_path);
        response.headers["Content-Type"] = mime_type;
        
        // Aggiungi charset per file di testo
        if (mime_type.find("text/") == 0 || mime_type == "application/javascript" || mime_type == "application/json") {
            response.headers["Content-Type"] += "; charset=UTF-8";
        }
        
        response.headers["Date"] = getCurrentHttpDate();
        response.headers["Server"] = "C++17 HTTP Server/1.0";
        response.headers["Accept-Ranges"] = "bytes";
        
        // Determina se usare chunked encoding
        if (file_size > HttpResponse::CHUNKED_THRESHOLD) {
            LOG_DEBUG("File is large, using chunked encoding");
            // Usa chunked encoding per file grandi
            response.is_chunked = true;
            response.file_path_for_chunking = normalized_path.string();
            response.headers["Transfer-Encoding"] = "chunked";
            // Non impostare Content-Length per chunked encoding
        } else {
            LOG_DEBUG("File is small, loading into memory");
            // Per file piccoli, leggi tutto in memoria
            std::ifstream file(normalized_path, std::ios::binary);
            if (!file) {
                throw std::runtime_error("Cannot open file");
            }
            
            // Leggi il contenuto binario
            response.body.resize(file_size);
            if (!file.read(response.body.data(), file_size)) {
                throw std::runtime_error("Failed to read file");
            }
            
            response.headers["Content-Length"] = std::to_string(file_size);
        }
        
        // Imposta cache control in base al tipo di file
        if (mime_type.find("image/") == 0 || mime_type.find("font/") == 0) {
            response.headers["Cache-Control"] = "public, max-age=86400"; // 24 ore per immagini e font
        } else if (mime_type.find("text/css") == 0 || mime_type.find("application/javascript") == 0) {
            response.headers["Cache-Control"] = "public, max-age=3600"; // 1 ora per CSS e JS
        } else if (mime_type.find("text/html") == 0) {
            response.headers["Cache-Control"] = "no-cache, must-revalidate"; // No cache per HTML
        } else {
            response.headers["Cache-Control"] = "no-cache"; // No cache per altri file
        }
        
        // Aggiungi Last-Modified header
        auto ftime = fs::last_write_time(normalized_path);
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        auto time_t = std::chrono::system_clock::to_time_t(sctp);
        std::tm* gmt_time = std::gmtime(&time_t);
        std::ostringstream last_modified;
        last_modified << std::put_time(gmt_time, "%a, %d %b %Y %H:%M:%S GMT");
        response.headers["Last-Modified"] = last_modified.str();
        
        // Aggiungi Content-Disposition per file scaricabili
        if (mime_type == "application/octet-stream" || 
            mime_type.find("application/zip") == 0 ||
            mime_type.find("application/x-") == 0) {
            response.headers["Content-Disposition"] = "attachment; filename=\"" + parsed.filename + "\"";
        }
        
        LOG_DEBUG("<<< Exiting handleFileRequest() - 200");
        return response;
        
    } catch (const std::exception& e) {
        LOG_ERROR("Exception in handleFileRequest: " + std::string(e.what()));
        response.status_code = 500;
        response.headers["Content-Type"] = "text/html; charset=UTF-8";
        response.headers["Date"] = getCurrentHttpDate();
        response.body = R"(<!DOCTYPE html>
<html>
<head>
    <title>500 Internal Server Error</title>
</head>
<body>
    <h1>500 Internal Server Error</h1>
    <p>An error occurred while reading the file.</p>
</body>
</html>)";
        LOG_DEBUG("<<< Exiting handleFileRequest() - 500 (exception)");
        return response;
    }
}

// Funzione deprecata - mantenuta per compatibilità
// Si consiglia di usare load_file_advanced per tutti i tipi di file
void load_html(std::string html_file, std::map<std::string, std::string>& response_headers, std::string& body) {
    LOG_DEBUG(">>> Entering load_html() - html_file: " + html_file);
    
    auto response_opt = generateHttpResponse(html_file);
    HttpResponse response = response_opt.value();
    body = response.getBody();
    response_headers = response.getHeaders();
    
    LOG_DEBUG("<<< Exiting load_html()");
}

// Funzione deprecata - mantenuta per compatibilità  
// Si consiglia di usare load_file_advanced per tutti i tipi di file
void load_file(const std::string& uri, const std::string& document_root, std::map<std::string, std::string>& response_headers, std::string& body) {
    LOG_DEBUG(">>> Entering load_file() - uri: " + uri + ", document_root: " + document_root);
    
    auto response_opt = handleFileRequest(uri, document_root);
    HttpResponse response = response_opt.value();
    body = response.getBody();
    response_headers = response.getHeaders();
    
    LOG_DEBUG("<<< Exiting load_file()");
}

// Struttura per gestire le risposte chunked
// Utilizzata da load_file_advanced per fornire informazioni dettagliate
// su come inviare la risposta (chunked o normale)
struct ChunkedFileResponse {
    std::map<std::string, std::string> headers;
    std::string file_path;          // Percorso del file per chunked encoding
    bool is_chunked;                // True se il file deve essere inviato a chunk
    size_t file_size;               // Dimensione del file
    int status_code;                // Codice di stato HTTP
    std::string error_body;         // Body della risposta (per errori o file piccoli)
};

// Funzione avanzata per file che restituisce informazioni per chunked encoding
ChunkedFileResponse load_file_advanced(const std::string& uri, const std::string& document_root) {
    LOG_DEBUG(">>> Entering load_file_advanced() - uri: " + uri + ", document_root: " + document_root);
    
    ChunkedFileResponse result;
    
    auto response_opt = handleFileRequest(uri, document_root);
    if (!response_opt) {
        LOG_ERROR("handleFileRequest returned no value");
        result.status_code = 500;
        result.is_chunked = false;
        result.error_body = "Internal server error";
        LOG_DEBUG("<<< Exiting load_file_advanced() - 500");
        return result;
    }
    
    HttpResponse response = response_opt.value();
    result.headers = response.getHeaders();
    result.status_code = response.status_code;
    
    if (response.isChunked()) {
        result.is_chunked = true;
        result.file_path = response.getFilePathForChunking();
        result.file_size = fs::file_size(result.file_path);
        LOG_DEBUG("Response is chunked, file_size: " + std::to_string(result.file_size));
    } else {
        result.is_chunked = false;
        result.error_body = response.getBody();
    }
    
    LOG_DEBUG("<<< Exiting load_file_advanced() - status: " + std::to_string(result.status_code));
    return result;
}

// Funzione helper per inviare un chunk
std::string formatChunk(const std::vector<char>& data, size_t size) {
    LOG_DEBUG(">>> Entering formatChunk() - size: " + std::to_string(size));
    
    std::ostringstream chunk;
    chunk << std::hex << size << "\r\n";
    chunk.write(data.data(), size);
    chunk << "\r\n";
    
    LOG_DEBUG("<<< Exiting formatChunk()");
    return chunk.str();
}

// Funzione per leggere e formattare il prossimo chunk da un file
std::string getNextChunk(std::ifstream& file, size_t chunk_size = 64 * 1024) {
    LOG_DEBUG(">>> Entering getNextChunk() - chunk_size: " + std::to_string(chunk_size));
    
    std::vector<char> buffer(chunk_size);
    file.read(buffer.data(), chunk_size);
    std::streamsize bytes_read = file.gcount();
    
    std::string result;
    if (bytes_read > 0) {
        result = formatChunk(buffer, bytes_read);
        LOG_DEBUG("Read " + std::to_string(bytes_read) + " bytes");
    } else {
        // Chunk finale
        result = "0\r\n\r\n";
        LOG_DEBUG("Sending final chunk");
    }
    
    LOG_DEBUG("<<< Exiting getNextChunk()");
    return result;
}

// Funzione helper per inviare tutti i dati attraverso il socket
bool sendAll(int socket, const char* buffer, size_t length) {
    LOG_DEBUG(">>> Entering sendAll() - socket: " + std::to_string(socket) + ", length: " + std::to_string(length));
    
    size_t total_sent = 0;
    
    while (total_sent < length) {
        ssize_t sent = send(socket, buffer + total_sent, length - total_sent, MSG_NOSIGNAL);
        
        if (sent < 0) {
            if (errno == EINTR) {
                // Interrupted system call, riprova
                LOG_DEBUG("Send interrupted, retrying...");
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket non bloccante, riprova dopo un breve delay
                LOG_DEBUG("Socket would block, sleeping...");
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            } else {
                // Errore reale
                LOG_ERROR("Error sending data: " + std::string(strerror(errno)));
                LOG_DEBUG("<<< Exiting sendAll() - error");
                return false;
            }
        } else if (sent == 0) {
            // Connessione chiusa
            LOG_WARNING("Connection closed during send");
            LOG_DEBUG("<<< Exiting sendAll() - connection closed");
            return false;
        }
        
        total_sent += sent;
        LOG_DEBUG("Sent " + std::to_string(sent) + " bytes, total: " + std::to_string(total_sent));
    }
    
    LOG_DEBUG("<<< Exiting sendAll() - success");
    return true;
}

// Funzione principale per gestire richieste HTTP
// Utilizza sempre load_file_advanced internamente per gestire qualsiasi tipo di file
// Supporta automaticamente chunked encoding per file > 10MB
void handleHttpRequest(const std::string& uri, const std::string& document_root, int client_socket) {
    LOG_DEBUG(">>> Entering handleHttpRequest() - uri: " + uri + ", document_root: " + document_root + 
             ", socket: " + std::to_string(client_socket));
    
    try {
        // Utilizza sempre load_file_advanced per qualsiasi tipo di file
        ChunkedFileResponse response = load_file_advanced(uri, document_root);
        
        // Costruisci e invia gli headers
        std::ostringstream headers_stream;
        headers_stream << "HTTP/1.1 " << response.status_code;
        switch (response.status_code) {
            case 200: headers_stream << " OK"; break;
            case 400: headers_stream << " Bad Request"; break;
            case 403: headers_stream << " Forbidden"; break;
            case 404: headers_stream << " Not Found"; break;
            case 500: headers_stream << " Internal Server Error"; break;
            default: headers_stream << " Unknown"; break;
        }
        headers_stream << "\r\n";
        
        // Aggiungi tutti gli headers dalla risposta
        for (const auto& [key, value] : response.headers) {
            headers_stream << key << ": " << value << "\r\n";
        }
        
        // Aggiungi Connection header se non presente
        if (response.headers.find("Connection") == response.headers.end()) {
            headers_stream << "Connection: keep-alive\r\n";
        }
        
        headers_stream << "\r\n";
        
        std::string headers_str = headers_stream.str();
        LOG_DEBUG("Sending headers...");
        if (!sendAll(client_socket, headers_str.c_str(), headers_str.length())) {
            LOG_ERROR("Failed to send headers");
            LOG_DEBUG("<<< Exiting handleHttpRequest() - header send failed");
            return;
        }
        
        // Invia il body
        if (response.is_chunked && response.status_code == 200 && !response.file_path.empty()) {
            LOG_DEBUG("Sending chunked file: " + response.file_path);
            // Invia file grande usando chunked encoding
            std::ifstream file(response.file_path, std::ios::binary);
            if (!file) {
                LOG_ERROR("Failed to open file for chunking: " + response.file_path);
                LOG_DEBUG("<<< Exiting handleHttpRequest() - file open failed");
                return;
            }
            
            std::vector<char> buffer(HttpResponse::CHUNK_SIZE);
            bool send_error = false;
            
            while (file.good() && !send_error) {
                file.read(buffer.data(), HttpResponse::CHUNK_SIZE);
                std::streamsize bytes_read = file.gcount();
                
                if (bytes_read > 0) {
                    // Invia la dimensione del chunk in esadecimale
                    std::ostringstream chunk_size_stream;
                    chunk_size_stream << std::hex << bytes_read << "\r\n";
                    std::string chunk_size_str = chunk_size_stream.str();
                    
                    if (!sendAll(client_socket, chunk_size_str.c_str(), chunk_size_str.length())) {
                        send_error = true;
                        break;
                    }
                    
                    // Invia i dati del chunk
                    if (!sendAll(client_socket, buffer.data(), bytes_read)) {
                        send_error = true;
                        break;
                    }
                    
                    // Invia CRLF dopo il chunk
                    if (!sendAll(client_socket, "\r\n", 2)) {
                        send_error = true;
                        break;
                    }
                }
            }
            
            if (!send_error) {
                // Invia il chunk finale
                LOG_DEBUG("Sending final chunk");
                if (!sendAll(client_socket, "0\r\n\r\n", 5)) {
                    LOG_ERROR("Failed to send final chunk");
                }
            } else {
                LOG_ERROR("Error occurred while sending chunks");
            }
            
            file.close();
            
        } else if (!response.error_body.empty()) {
            LOG_DEBUG("Sending normal body, size: " + std::to_string(response.error_body.length()));
            // Invia body normale (file piccolo o pagina di errore)
            if (!sendAll(client_socket, response.error_body.c_str(), response.error_body.length())) {
                LOG_ERROR("Failed to send response body");
            }
        }
        
        LOG_DEBUG("<<< Exiting handleHttpRequest() - success");
        
    } catch (const std::exception& e) {
        LOG_ERROR("Exception in handleHttpRequest: " + std::string(e.what()));
        
        // Invia una risposta di errore 500
        std::ostringstream error_response;
        error_response << "HTTP/1.1 500 Internal Server Error\r\n";
        error_response << "Content-Type: text/html; charset=UTF-8\r\n";
        error_response << "Date: " << getCurrentHttpDate() << "\r\n";
        error_response << "Connection: close\r\n";
        
        std::string error_body = R"(<!DOCTYPE html>
<html>
<head>
    <title>500 Internal Server Error</title>
</head>
<body>
    <h1>500 Internal Server Error</h1>
    <p>An unexpected error occurred while processing your request.</p>
</body>
</html>)";
        
        error_response << "Content-Length: " << error_body.length() << "\r\n";
        error_response << "\r\n";
        error_response << error_body;
        
        std::string response_str = error_response.str();
        sendAll(client_socket, response_str.c_str(), response_str.length());
        
        LOG_DEBUG("<<< Exiting handleHttpRequest() - exception handled");
    }
}