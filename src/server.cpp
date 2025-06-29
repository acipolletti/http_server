// src/server.cpp
#include <atomic>
#include <memory>
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <filesystem>
#include <chrono>
#include <cstring>
#include <csignal>
#include <queue>
#include <poll.h>
#include <map>
#include <sstream>
#include <algorithm>
#include <errno.h>
#include "nlohmann/json.hpp"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include "logger.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include "auth.hpp"
#include "auth_routes.hpp"
#include "check_mime_type.hpp"
#include "user_file_manager.hpp"
#include "file_routes.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;
extern void load_html(std::string html_file,std::map<std::string, std::string>& response_headers,std::string& body);
extern void handleHttpRequest(const std::string& uri, const std::string& document_root,int);
extern std::string urlEncode(const std::string&),urlDecode(const std::string&);

// Global variables for signal handling
static std::atomic<bool> g_running(true);
static std::condition_variable g_cv;
static std::mutex g_cv_mutex;

std::unique_ptr<Logger> logger;

void signalHandler(int signum) {
    std::cout << "\nShutting down server..." << std::endl;
    g_running.store(false);
    g_cv.notify_all();
}

struct SSLConfig {
    std::string cert_path;
    std::string key_path;
};

struct ServerConfig {
    std::string host;
    int port;
    int http_port;
    bool enable_http;
    int threads;
    int timeout;
    std::string home_folder;
    SSLConfig ssl;

    struct KeepAlive {
        bool enabled = true;
        int max_requests = 100;
        int timeout = 15;
    } keepalive;

    struct Logging {
        LogLevel level;
        std::string file;
        bool console_output;
    } logging;
    
    struct Authentication {
        bool enabled;
        std::string database_path;
        int session_lifetime;
        bool extend_session_on_activity;
        struct Smtp {
            std::string server;
            std::string username;
            std::string password;
            std::string from;
        } smtp;
    } authentication;

    struct Route {
        std::string path;
        std::string method;
        std::string local_file;
    };

    std::vector<Route> routes;
};

// Thread pool for handling connections
class ThreadPool {
public:
    ThreadPool(size_t num_threads) : stop(false) {
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread& worker : workers) {
            worker.join();
        }
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

ServerConfig parse_config(const std::string& config_path) {
    ServerConfig config;
    std::ifstream config_file(config_path);
    if (!config_file.is_open()) {
        throw std::runtime_error("Failed to open config file: " + config_path);
    }

    json j;
    config_file >> j;

    // Parse keep-alive settings
    if (j["server"].contains("keepalive")) {
        auto ka = j["server"]["keepalive"];
        config.keepalive.enabled = ka.value("enabled", true);
        config.keepalive.max_requests = ka.value("max_requests", 100);
        config.keepalive.timeout = ka.value("timeout", 300);
        
    }
    
    // Server settings
    config.host = j["server"]["host"];
    config.port = j["server"]["port"];
    config.http_port = j["server"].value("http_port", 8080);
    config.enable_http = j["server"].value("enable_http", false);
    config.threads = j["server"]["threads"];
    config.timeout = j["server"]["timeout"];
    config.home_folder = j["server"]["home_folder"];

    // Logging settings
    config.logging.console_output = j["logging"]["console"];
    config.logging.file = j["logging"]["file"];
    std::string level_str = j["logging"]["level"];
    if (level_str == "debug") {
        config.logging.level = LogLevel::DEBUG;
    } else if (level_str == "info") {
        config.logging.level = LogLevel::INFO;
    } else if (level_str == "warning") {
        config.logging.level = LogLevel::WARNING;
    } else if (level_str == "error") {
        config.logging.level = LogLevel::ERROR;
    } else {
        config.logging.level = LogLevel::INFO;
    }

    // SSL settings
    config.ssl.cert_path = j["server"]["ssl"]["cert_path"];
    config.ssl.key_path = j["server"]["ssl"]["key_path"];
    
    // Authentication settings
    if (j.contains("authentication")) {
        config.authentication.enabled = j["authentication"].value("enabled", false);
        config.authentication.database_path = j["authentication"].value("database_path", "users.db");
        config.authentication.session_lifetime = j["authentication"].value("session_lifetime", 86400);
        config.authentication.extend_session_on_activity = j["authentication"].value("extend_session_on_activity", true);
        
        if (j["authentication"].contains("smtp")) {
            config.authentication.smtp.server = j["authentication"]["smtp"].value("server", "");
            config.authentication.smtp.username = j["authentication"]["smtp"].value("username", "");
            config.authentication.smtp.password = j["authentication"]["smtp"].value("password", "");
            config.authentication.smtp.from = j["authentication"]["smtp"].value("from", "noreply@localhost");
        }
    } else {
        config.authentication.enabled = false;
    }

    // Routes
    for (const auto& route : j["routes"]) {
        ServerConfig::Route r;
        r.path = route["path"];
        r.method = route["method"];
        r.local_file = route["local_file"];
        config.routes.push_back(r);
    }

    return config;
}

// Helper function to check if a route requires authentication
bool isProtectedRoute(const std::string& path) {
    // Public routes that don't require authentication
    std::vector<std::string> public_routes = {
        "/", 
        "/auth/login", 
        "/auth/register", 
        "/auth/verify",
        "/api/status", 
        "/health",
        "/static/",
        "/favicon.ico"
    };
    
    // Check if route is explicitly public
    for (const auto& route : public_routes) {
        if (path == route || (route.back() == '/' && path.find(route) == 0)) {
            return false;
        }
    }
    
    // All other routes are protected by default
    return true;
}

// HTTP Request structure and parser

struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::map<std::string, std::string> headers;
    std::string body;
    bool complete = false;
};

// Parse HTTP request from raw string
HttpRequest parseHttpRequest(const std::string& raw_request) {
    HttpRequest request;
    
    // Find end of headers
    size_t header_end = raw_request.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return request; // Incomplete request
    }
    
    std::string headers_section = raw_request.substr(0, header_end);
    std::istringstream header_stream(headers_section);
    std::string line;
    
    // Parse request line
    if (std::getline(header_stream, line)) {
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        std::istringstream request_line(line);
        request_line >> request.method >> request.path >> request.version;
        
        // Remove query string from path
        size_t query_pos = request.path.find('?');
        if (query_pos != std::string::npos) {
            request.path = request.path.substr(0, query_pos);
        }
    }
    
    // Parse headers
    while (std::getline(header_stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            // Trim whitespace from value
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            // Convert header key to lowercase for case-insensitive comparison
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            request.headers[key] = value;
        }
    }
    
    // Extract body if present
    size_t body_start = header_end + 4;
    if (body_start < raw_request.length()) {
        request.body = raw_request.substr(body_start);
    }
    
    request.complete = true;
    return request;
}

// Properly handle SSL read with all possible states
ssize_t sslRead(SSL* ssl, char* buffer, size_t buffer_size, Logger* logger) {
    logger->log(LogLevel::DEBUG, ">>> Entering sslRead() - buffer_size: " + std::to_string(buffer_size));
    
    int bytes_read = SSL_read(ssl, buffer, buffer_size);
    
    if (bytes_read > 0) {
        logger->log(LogLevel::DEBUG, "<<< Exiting sslRead() - bytes_read: " + std::to_string(bytes_read));
        return bytes_read;
    }
    
    int ssl_error = SSL_get_error(ssl, bytes_read);
    
    switch (ssl_error) {
        case SSL_ERROR_ZERO_RETURN:
            // SSL connection has been closed
            logger->log(LogLevel::DEBUG, "SSL connection closed by peer");
            logger->log(LogLevel::DEBUG, "<<< Exiting sslRead() - returning 0");
            return 0;
            
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            // Non-blocking operation, need to retry
            // For blocking sockets, this shouldn't happen
            logger->log(LogLevel::DEBUG, "SSL wants read/write - retrying");
            errno = EAGAIN;
            logger->log(LogLevel::DEBUG, "<<< Exiting sslRead() - returning -1 (EAGAIN)");
            return -1;
            
        case SSL_ERROR_SYSCALL:
            if (bytes_read == 0) {
                // EOF
                logger->log(LogLevel::DEBUG, "SSL EOF reached");
                logger->log(LogLevel::DEBUG, "<<< Exiting sslRead() - returning 0");
                return 0;
            } else {
                // Check errno for the actual error
                logger->log(LogLevel::ERROR, "SSL syscall error: " + std::string(strerror(errno)));
                logger->log(LogLevel::DEBUG, "<<< Exiting sslRead() - returning -1");
                return -1;
            }
            
        case SSL_ERROR_SSL:
            logger->log(LogLevel::ERROR, "SSL protocol error");
            logger->log(LogLevel::DEBUG, "<<< Exiting sslRead() - returning -1");
            return -1;
            
        default:
            logger->log(LogLevel::ERROR, "Unknown SSL error: " + std::to_string(ssl_error));
            logger->log(LogLevel::DEBUG, "<<< Exiting sslRead() - returning -1");
            return -1;
    }
}

// Properly handle SSL write with all possible states
ssize_t sslWrite(SSL* ssl, const char* buffer, size_t buffer_size, Logger* logger) {
    logger->log(LogLevel::DEBUG, ">>> Entering sslWrite() - buffer_size: " + std::to_string(buffer_size));
    
    int total_written = 0;
    
    while (total_written < buffer_size) {
        int bytes_written = SSL_write(ssl, buffer + total_written, buffer_size - total_written);
        
        if (bytes_written > 0) {
            total_written += bytes_written;
            continue;
        }
        
        int ssl_error = SSL_get_error(ssl, bytes_written);
        
        switch (ssl_error) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                // For blocking sockets, just retry
                continue;
                
            case SSL_ERROR_ZERO_RETURN:
                logger->log(LogLevel::ERROR, "SSL connection closed during write");
                logger->log(LogLevel::DEBUG, "<<< Exiting sslWrite() - returning -1");
                return -1;
                
            case SSL_ERROR_SYSCALL:
                logger->log(LogLevel::ERROR, "SSL write syscall error: " + std::string(strerror(errno)));
                logger->log(LogLevel::DEBUG, "<<< Exiting sslWrite() - returning -1");
                return -1;
                
            case SSL_ERROR_SSL:
                logger->log(LogLevel::ERROR, "SSL write protocol error");
                logger->log(LogLevel::DEBUG, "<<< Exiting sslWrite() - returning -1");
                return -1;
                
            default:
                logger->log(LogLevel::ERROR, "Unknown SSL write error: " + std::to_string(ssl_error));
                logger->log(LogLevel::DEBUG, "<<< Exiting sslWrite() - returning -1");
                return -1;
        }
    }
    
    logger->log(LogLevel::DEBUG, "<<< Exiting sslWrite() - total_written: " + std::to_string(total_written));
    return total_written;
}

// Read data from socket (handles both SSL and non-SSL)
ssize_t readFromSocket(int socket, SSL* ssl, char* buffer, size_t buffer_size, bool use_ssl, Logger* logger) {
    logger->log(LogLevel::DEBUG, ">>> Entering readFromSocket() - socket: " + std::to_string(socket) + 
                ", buffer_size: " + std::to_string(buffer_size) + ", use_ssl: " + std::to_string(use_ssl));
    
    ssize_t result;
    if (use_ssl && ssl) {
        result = sslRead(ssl, buffer, buffer_size, logger);
    } else {
        result = recv(socket, buffer, buffer_size, 0);
        if (result < 0 && errno == EINTR) {
            // Interrupted by signal, retry
            result = recv(socket, buffer, buffer_size, 0);
        }
    }
    
    logger->log(LogLevel::DEBUG, "<<< Exiting readFromSocket() - result: " + std::to_string(result));
    return result;
}

// Write data to socket (handles both SSL and non-SSL)
ssize_t writeToSocket(int socket, SSL* ssl, const char* buffer, size_t buffer_size, bool use_ssl, Logger* logger) {
    logger->log(LogLevel::DEBUG, ">>> Entering writeToSocket() - socket: " + std::to_string(socket) + 
                ", buffer_size: " + std::to_string(buffer_size) + ", use_ssl: " + std::to_string(use_ssl));
    
    if (use_ssl && ssl) {
        ssize_t result = sslWrite(ssl, buffer, buffer_size, logger);
        logger->log(LogLevel::DEBUG, "<<< Exiting writeToSocket() - result: " + std::to_string(result));
        return result;
    } else {
        size_t total_sent = 0;
        while (total_sent < buffer_size) {
            ssize_t sent = send(socket, buffer + total_sent, buffer_size - total_sent, MSG_NOSIGNAL);
            if (sent < 0) {
                if (errno == EINTR) continue; // Retry on interrupt
                if (errno == EPIPE || errno == ECONNRESET) {
                    logger->log(LogLevel::DEBUG, "Connection closed by peer during write");
                    logger->log(LogLevel::DEBUG, "<<< Exiting writeToSocket() - returning -1");
                    return -1;
                }
                logger->log(LogLevel::ERROR, "Socket write error: " + std::string(strerror(errno)));
                logger->log(LogLevel::DEBUG, "<<< Exiting writeToSocket() - returning -1");
                return -1;
            }
            total_sent += sent;
        }
        logger->log(LogLevel::DEBUG, "<<< Exiting writeToSocket() - total_sent: " + std::to_string(total_sent));
        return total_sent;
    }
}

// Updated sendHttpResponse with complete response logging
// Updated sendHttpResponse function in server.cpp
void sendHttpResponse(int client_socket, bool use_ssl, SSL* ssl,
                     int status_code, const std::map<std::string, std::string>& headers,
                     const std::string& body, Logger* logger) {
    logger->log(LogLevel::DEBUG, ">>> Entering sendHttpResponse() - status_code: " + std::to_string(status_code) + 
                ", use_ssl: " + std::to_string(use_ssl));
    
    std::string response = "HTTP/1.1 " + std::to_string(status_code);
    
    // Add status text
    switch(status_code) {
        case 200: response += " OK"; break;
        case 301: response += " Moved Permanently"; break;
        case 302: response += " Found"; break;
        case 400: response += " Bad Request"; break;
        case 401: response += " Unauthorized"; break;
        case 403: response += " Forbidden"; break;
        case 404: response += " Not Found"; break;
        case 413: response += " Payload Too Large"; break;
        case 500: response += " Internal Server Error"; break;
        default: response += " OK"; break;
    }
    response += "\r\n";
    
    // Add headers - INCLUDING Set-Cookie headers
    for (const auto& header : headers) {
        response += header.first + ": " + header.second + "\r\n";
        // Log important headers for debugging
        if (header.first == "Set-Cookie") {
            logger->log(LogLevel::INFO, "Setting cookie: " + header.second);
        }
    }
    
    // Add content length if not present
    if (headers.find("Content-Length") == headers.end()) {
        response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    
    // Add security headers (but don't override existing ones)
    if (headers.find("X-Content-Type-Options") == headers.end()) {
        response += "X-Content-Type-Options: nosniff\r\n";
    }
    if (headers.find("X-Frame-Options") == headers.end()) {
        response += "X-Frame-Options: DENY\r\n";
    }
    
    response += "\r\n";
    
    
    // ===== LOG HEADER RESPONSE =====
    logger->log(LogLevel::INFO, "===== COMPLETE RESPONSE =====");
    logger->log(LogLevel::INFO, "Status Line: HTTP/1.1 " + std::to_string(status_code) + 
                " " + (status_code == 200 ? "OK" : 
                      status_code == 301 ? "Moved Permanently" : 
                      status_code == 302 ? "Found" :
                      status_code == 400 ? "Bad Request" : 
                      status_code == 401 ? "Unauthorized" : 
                      status_code == 403 ? "Forbidden" : 
                      status_code == 404 ? "Not Found" : 
                      status_code == 413 ? "Payload Too Large" : 
                      status_code == 500 ? "Internal Server Error" : "OK"));
    
    logger->log(LogLevel::INFO, "Headers:");
    for (const auto& header : headers) {
        logger->log(LogLevel::INFO, "  " + header.first + ": " + header.second);
    }
    // Log additional headers that were added
    if (headers.find("Content-Length") == headers.end()) {
        logger->log(LogLevel::INFO, "  Content-Length: " + std::to_string(body.size()));
    }
    if (headers.find("X-Content-Type-Options") == headers.end()) {
        logger->log(LogLevel::INFO, "  X-Content-Type-Options: nosniff");
    }
    if (headers.find("X-Frame-Options") == headers.end()) {
        logger->log(LogLevel::INFO, "  X-Frame-Options: DENY");
    }
    /*
    if (!body.empty()) {
        logger->log(LogLevel::INFO, "Body (" + std::to_string(body.length()) + " bytes):");
        // Limit body logging to prevent huge logs
        if (body.length() <= 1024) {
            logger->log(LogLevel::INFO, body);
        } else {
            logger->log(LogLevel::INFO, body.substr(0, 1024) + "\n... (truncated, total " + 
                       std::to_string(body.length()) + " bytes)");
        }
    } else {
        logger->log(LogLevel::INFO, "Body: (empty)");
    }*/
    logger->log(LogLevel::INFO, "============================");
    

    // Add body to response
    response += body;
    
    logger->log(LogLevel::DEBUG, "Full response size: " + std::to_string(response.size()));
    
    // Send complete response
    if (use_ssl && ssl) {
        size_t total_sent = 0;
        while (total_sent < response.size()) {
            int sent = SSL_write(ssl, response.c_str() + total_sent, response.size() - total_sent);
            
            if (sent > 0) {
                total_sent += sent;
                continue;
            }
            
            int ssl_error = SSL_get_error(ssl, sent);
            switch (ssl_error) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    continue;
                    
                default:
                    logger->log(LogLevel::ERROR, "SSL write error: " + std::to_string(ssl_error));
                    logger->log(LogLevel::DEBUG, "<<< Exiting sendHttpResponse() - SSL write error");
                    return;
            }
        }
    } else {
        size_t total_sent = 0;
        while (total_sent < response.size()) {
            ssize_t sent = send(client_socket, response.c_str() + total_sent, 
                              response.size() - total_sent, MSG_NOSIGNAL);
            if (sent < 0) {
                if (errno == EINTR) continue;
                if (errno == EPIPE || errno == ECONNRESET) {
                    logger->log(LogLevel::DEBUG, "Connection closed during write");
                    logger->log(LogLevel::DEBUG, "<<< Exiting sendHttpResponse() - connection closed");
                    return;
                }
                logger->log(LogLevel::ERROR, "Socket write error: " + std::string(strerror(errno)));
                logger->log(LogLevel::DEBUG, "<<< Exiting sendHttpResponse() - socket error");
                return;
            }
            total_sent += sent;
        }
    }
    
    logger->log(LogLevel::DEBUG, "<<< Exiting sendHttpResponse() - success, sent " + 
                std::to_string(response.size()) + " bytes");
}
std::string parseChunkedBody(const std::string& chunked_data, Logger* logger) {
    logger->log(LogLevel::DEBUG, ">>> Entering parseChunkedBody() - data_size: " + std::to_string(chunked_data.size()));
    
    std::string result;
    size_t pos = 0;
    
    while (pos < chunked_data.length()) {
        // Find chunk size line
        size_t line_end = chunked_data.find("\r\n", pos);
        if (line_end == std::string::npos) break;
        
        std::string size_line = chunked_data.substr(pos, line_end - pos);
        
        // Parse chunk size (hexadecimal)
        size_t chunk_size = 0;
        try {
            chunk_size = std::stoull(size_line, nullptr, 16);
        } catch (const std::exception& e) {
            logger->log(LogLevel::ERROR, "Invalid chunk size: " + size_line);
            break;
        }
        
        // Check for last chunk
        if (chunk_size == 0) {
            // Skip trailer headers if any
            pos = chunked_data.find("\r\n\r\n", line_end);
            break;
        }
        
        // Extract chunk data
        pos = line_end + 2; // Skip \r\n
        if (pos + chunk_size > chunked_data.length()) {
            logger->log(LogLevel::ERROR, "Incomplete chunk data");
            break;
        }
        
        result.append(chunked_data.substr(pos, chunk_size));
        pos += chunk_size + 2; // Skip chunk data and trailing \r\n
    }
    
    logger->log(LogLevel::DEBUG, "<<< Exiting parseChunkedBody() - result_size: " + std::to_string(result.size()));
    return result;
}

// Read chunked body from socket
std::string readChunkedBody(int socket, SSL* ssl, bool use_ssl, Logger* logger, 
                           const struct timeval& timeout) {
    logger->log(LogLevel::DEBUG, ">>> Entering readChunkedBody()");
    
    std::string body;
    char buffer[4096];
    
    while (true) {
        // Read chunk size line
        std::string size_line;
        while (size_line.find("\r\n") == std::string::npos) {
            ssize_t bytes = readFromSocket(socket, ssl, buffer, 1, use_ssl, logger);
            if (bytes <= 0) {
                logger->log(LogLevel::ERROR, "Error reading chunk size");
                logger->log(LogLevel::DEBUG, "<<< Exiting readChunkedBody() - error");
                return body;
            }
            size_line.append(buffer, bytes);
            
            // Prevent infinite loop
            if (size_line.length() > 100) {
                logger->log(LogLevel::ERROR, "Chunk size line too long");
                logger->log(LogLevel::DEBUG, "<<< Exiting readChunkedBody() - chunk size too long");
                return body;
            }
        }
        
        // Parse chunk size
        size_t chunk_size = 0;
        try {
            // Remove \r\n and parse hex
            std::string hex_size = size_line.substr(0, size_line.find("\r\n"));
            // Handle chunk extensions (ignore them)
            size_t semicolon = hex_size.find(';');
            if (semicolon != std::string::npos) {
                hex_size = hex_size.substr(0, semicolon);
            }
            chunk_size = std::stoull(hex_size, nullptr, 16);
        } catch (const std::exception& e) {
            logger->log(LogLevel::ERROR, "Invalid chunk size");
            logger->log(LogLevel::DEBUG, "<<< Exiting readChunkedBody() - invalid chunk size");
            return body;
        }
        
        // Check for last chunk
        if (chunk_size == 0) {
            // Read trailing headers (if any) until \r\n\r\n
            std::string trailer;
            while (trailer.find("\r\n\r\n") == std::string::npos) {
                ssize_t bytes = readFromSocket(socket, ssl, buffer, 
                                             sizeof(buffer) - 1, use_ssl, logger);
                if (bytes <= 0) break;
                trailer.append(buffer, bytes);
                if (trailer.length() > 4096) break; // Prevent DoS
            }
            break;
        }
        
        // Read chunk data
        size_t read_so_far = 0;
        while (read_so_far < chunk_size) {
            size_t to_read = std::min(chunk_size - read_so_far, sizeof(buffer));
            ssize_t bytes = readFromSocket(socket, ssl, buffer, to_read, use_ssl, logger);
            if (bytes <= 0) {
                logger->log(LogLevel::ERROR, "Error reading chunk data");
                logger->log(LogLevel::DEBUG, "<<< Exiting readChunkedBody() - error reading chunk");
                return body;
            }
            body.append(buffer, bytes);
            read_so_far += bytes;
        }
        
        // Read trailing \r\n after chunk
        char crlf[2];
        ssize_t bytes = readFromSocket(socket, ssl, crlf, 2, use_ssl, logger);
        if (bytes != 2 || crlf[0] != '\r' || crlf[1] != '\n') {
            logger->log(LogLevel::WARNING, "Missing CRLF after chunk");
        }
        
        // Check body size limit
        if (body.length() > 10 * 1024 * 1024) { // 10MB limit
            logger->log(LogLevel::ERROR, "Chunked body too large");
            logger->log(LogLevel::DEBUG, "<<< Exiting readChunkedBody() - body too large");
            return body;
        }
    }
    
    logger->log(LogLevel::DEBUG, "<<< Exiting readChunkedBody() - body_size: " + std::to_string(body.size()));
    return body;
}

// Determine if request should have a body
bool shouldHaveBody(const std::string& method, const std::map<std::string, std::string>& headers) {
    logger->log(LogLevel::DEBUG, ">>> Entering shouldHaveBody() - method: " + method);
    
    // Methods that typically don't have bodies
    if (method == "GET" || method == "HEAD" || method == "DELETE" || 
        method == "OPTIONS" || method == "TRACE") {
        
        // But check if Content-Length or Transfer-Encoding is present
        if (headers.find("content-length") != headers.end() ||
            headers.find("transfer-encoding") != headers.end()) {
            logger->log(LogLevel::DEBUG, "<<< Exiting shouldHaveBody() - returning true (headers present)");
            return true;
        }
        logger->log(LogLevel::DEBUG, "<<< Exiting shouldHaveBody() - returning false");
        return false;
    }
    
    // POST, PUT, PATCH typically have bodies
    logger->log(LogLevel::DEBUG, "<<< Exiting shouldHaveBody() - returning true");
    return true;
}

int create_server_socket(const std::string& host, int port, Logger* logger) {
    logger->log(LogLevel::DEBUG, ">>> Entering create_server_socket() - host: " + host + ", port: " + std::to_string(port));
    
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        logger->log(LogLevel::ERROR, "Failed to create socket");
        logger->log(LogLevel::DEBUG, "<<< Exiting create_server_socket() - returning -1");
        return -1;
    }

    // Set socket options for reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        logger->log(LogLevel::ERROR, "setsockopt failed");
        close(server_socket);
        logger->log(LogLevel::DEBUG, "<<< Exiting create_server_socket() - returning -1");
        return -1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        logger->log(LogLevel::ERROR, "Invalid address: " + host);
        close(server_socket);
        logger->log(LogLevel::DEBUG, "<<< Exiting create_server_socket() - returning -1");
        return -1;
    }

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        logger->log(LogLevel::ERROR, "Bind failed on port " + std::to_string(port) + ": " + std::string(strerror(errno)));
        close(server_socket);
        logger->log(LogLevel::DEBUG, "<<< Exiting create_server_socket() - returning -1");
        return -1;
    }

    if (listen(server_socket, SOMAXCONN) < 0) {
        logger->log(LogLevel::ERROR, "Listen failed");
        close(server_socket);
        logger->log(LogLevel::DEBUG, "<<< Exiting create_server_socket() - returning -1");
        return -1;
    }

    // Set socket to non-blocking mode
    int flags = fcntl(server_socket, F_GETFL, 0);
    if (flags == -1 || fcntl(server_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
        logger->log(LogLevel::ERROR, "Failed to set socket to non-blocking");
        close(server_socket);
        logger->log(LogLevel::DEBUG, "<<< Exiting create_server_socket() - returning -1");
        return -1;
    }

    logger->log(LogLevel::DEBUG, "<<< Exiting create_server_socket() - returning " + std::to_string(server_socket));
    return server_socket;
}

// Complete handle_client with proper SSL/TLS handling
// Updated handle_client function with complete request/response logging
// Updated handle_client function with complete request/response logging
void handle_client(SSL_CTX* ctx, const ServerConfig& config, int client_socket, 
                  Logger* logger, const std::unordered_map<std::string, std::string>& mime_types,
                  Auth::AuthManager* auth_manager, AuthRoutes::RouteHandler* auth_routes,
                  FileManager::UserFileManager* file_manager, FileRoutes::FileRouteHandler* file_routes,
                  bool use_ssl = true) {
    logger->log(LogLevel::DEBUG, ">>> Entering handle_client() - client_socket: " + std::to_string(client_socket) + 
                ", use_ssl: " + std::to_string(use_ssl));
    
    SSL* ssl = nullptr;
    
    // Connection state for keep-alive
    struct ConnectionState {
        int requests_handled = 0;
        bool should_close = false;
        std::chrono::steady_clock::time_point last_activity;
    } conn_state;
    
    // Keep-alive configuration
    bool ka_enabled = config.keepalive.enabled;
    int ka_max_requests = config.keepalive.max_requests;
    int ka_timeout_seconds = config.keepalive.timeout;
    
    // Set socket to blocking mode
    int flags = fcntl(client_socket, F_GETFL, 0);
    if (flags != -1) {
        fcntl(client_socket, F_SETFL, flags & ~O_NONBLOCK);
    }
    
    // SSL handshake for HTTPS connections
    if (use_ssl) {
        ssl = SSL_new(ctx);
        if (!ssl) {
            logger->log(LogLevel::ERROR, "Failed to create SSL object");
            close(client_socket);
            logger->log(LogLevel::DEBUG, "<<< Exiting handle_client() - SSL creation failed");
            return;
        }

        if (!SSL_set_fd(ssl, client_socket)) {
            logger->log(LogLevel::ERROR, "Failed to set file descriptor for SSL");
            SSL_free(ssl);
            close(client_socket);
            logger->log(LogLevel::DEBUG, "<<< Exiting handle_client() - SSL_set_fd failed");
            return;
        }

        int handshake_result = SSL_accept(ssl);
        if (handshake_result <= 0) {
            int ssl_error = SSL_get_error(ssl, handshake_result);
            logger->log(LogLevel::ERROR, "SSL handshake failed with error: " + std::to_string(ssl_error));
            if (ssl_error == SSL_ERROR_SSL) {
                char err_buf[256];
                ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
                logger->log(LogLevel::ERROR, "SSL error details: " + std::string(err_buf));
            }
            SSL_free(ssl);
            close(client_socket);
            logger->log(LogLevel::DEBUG, "<<< Exiting handle_client() - SSL handshake failed");
            return;
        }
        
        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
        if (cipher) {
            logger->log(LogLevel::DEBUG, "SSL handshake successful, cipher: " + 
                       std::string(SSL_CIPHER_get_name(cipher)));
        }
    }

    // Keep-alive loop - handle multiple requests on same connection
    while (!conn_state.should_close && g_running.load()) {
        conn_state.last_activity = std::chrono::steady_clock::now();
        
        // Set socket timeout based on whether we've already handled requests
        struct timeval timeout;
        if (conn_state.requests_handled > 0) {
            timeout.tv_sec = ka_timeout_seconds;
            logger->log(LogLevel::DEBUG, "Setting keep-alive timeout: " + std::to_string(ka_timeout_seconds) + " seconds");
        } else {
            timeout.tv_sec = config.timeout;
            logger->log(LogLevel::DEBUG, "Setting initial timeout: " + std::to_string(config.timeout) + " seconds");
        }
        timeout.tv_usec = 0;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        // Read HTTP request headers
        std::string request_buffer;
        char temp_buffer[4096];
        bool headers_complete = false;
        const size_t max_header_size = 8192;
        
        // Phase 1: Read headers
        logger->log(LogLevel::DEBUG, "Reading request headers for request #" + 
                    std::to_string(conn_state.requests_handled + 1) + "...");
        
        while (!headers_complete) {
            ssize_t bytes_received = readFromSocket(client_socket, ssl, temp_buffer, 
                                                  sizeof(temp_buffer) - 1, use_ssl, logger);
            
            if (bytes_received <= 0) {
                if (bytes_received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (conn_state.requests_handled > 0) {
                        logger->log(LogLevel::DEBUG, "Keep-alive timeout after " + 
                                   std::to_string(conn_state.requests_handled) + " requests");
                    } else {
                        logger->log(LogLevel::WARNING, "Socket timeout on first request");
                    }
                } else if (bytes_received == 0) {
                    if (conn_state.requests_handled > 0) {
                        logger->log(LogLevel::DEBUG, "Client closed keep-alive connection after " + 
                                   std::to_string(conn_state.requests_handled) + " requests");
                    } else {
                        logger->log(LogLevel::DEBUG, "Client closed connection before sending request");
                    }
                }
                conn_state.should_close = true;
                break;
            }
            
            temp_buffer[bytes_received] = '\0';
            request_buffer.append(temp_buffer, bytes_received);
            
            size_t header_end = request_buffer.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                headers_complete = true;
            }
            
            if (request_buffer.size() > max_header_size) {
                logger->log(LogLevel::WARNING, "Request headers too large");
                std::map<std::string, std::string> error_headers = {
                    {"Content-Type", "text/plain"},
                    {"Connection", "close"}
                };
                sendHttpResponse(client_socket, use_ssl, ssl, 413, error_headers, 
                               "Request header too large", logger);
                conn_state.should_close = true;
                break;
            }
        }
        
        if (conn_state.should_close) {
            break;
        }
        
        // Parse the request headers
        logger->log(LogLevel::DEBUG, "Parsing HTTP request...");
        HttpRequest request = parseHttpRequest(request_buffer);
        if (!request.complete) {
            logger->log(LogLevel::WARNING, "Failed to parse HTTP request");
            std::map<std::string, std::string> error_headers = {
                {"Content-Type", "text/plain"},
                {"Connection", "close"}
            };
            sendHttpResponse(client_socket, use_ssl, ssl, 400, error_headers, 
                           "Bad Request", logger);
            conn_state.should_close = true;
            break;
        }
        
        // Log the request
        logger->log(LogLevel::DEBUG, "Request #" + std::to_string(conn_state.requests_handled + 1) + 
                    ": " + request.method + " " + request.path);
        
        // Determine if we should keep connection alive BEFORE incrementing the counter
        bool keep_alive = false;
        if (ka_enabled && (conn_state.requests_handled + 1) < ka_max_requests) {
            auto conn_it = request.headers.find("connection");
            if (conn_it != request.headers.end()) {
                std::string conn_value = conn_it->second;
                std::transform(conn_value.begin(), conn_value.end(), conn_value.begin(), ::tolower);
                
                if (conn_value.find("close") != std::string::npos) {
                    keep_alive = false;
                    conn_state.should_close = true;
                    logger->log(LogLevel::DEBUG, "Client requested connection close");
                } else if (conn_value.find("keep-alive") != std::string::npos) {
                    keep_alive = true;
                }
            } else {
                // Default behavior based on HTTP version
                keep_alive = (request.version == "HTTP/1.1");
            }
            
            logger->log(LogLevel::DEBUG, "Keep-alive decision: " + std::string(keep_alive ? "true" : "false") + 
                       " (requests handled: " + std::to_string(conn_state.requests_handled) + 
                       ", max: " + std::to_string(ka_max_requests) + ")");
        } else {
            conn_state.should_close = true;
            logger->log(LogLevel::DEBUG, "Keep-alive disabled or max requests reached");
        }
        
        // Phase 2: Read body if needed
        bool has_body = shouldHaveBody(request.method, request.headers);
        
        if (has_body) {
            logger->log(LogLevel::DEBUG, "Reading request body...");
            auto cl_it = request.headers.find("content-length");
            if (cl_it != request.headers.end()) {
                try {
                    size_t content_length = std::stoull(cl_it->second);
                    
                    if (content_length > 10 * 1024 * 1024) {
                        logger->log(LogLevel::WARNING, "Content-Length too large: " + std::to_string(content_length));
                        std::map<std::string, std::string> error_headers = {
                            {"Content-Type", "text/plain"},
                            {"Connection", "close"}
                        };
                        sendHttpResponse(client_socket, use_ssl, ssl, 413, error_headers, 
                                       "Request body too large", logger);
                        conn_state.should_close = true;
                        break;
                    }
                    
                    size_t header_end = request_buffer.find("\r\n\r\n") + 4;
                    size_t current_body_size = request_buffer.length() - header_end;
                    
                    if (current_body_size < content_length) {
                        request.body = request_buffer.substr(header_end);
                        
                        while (request.body.length() < content_length) {
                            size_t remaining = content_length - request.body.length();
                            size_t to_read = std::min(remaining, sizeof(temp_buffer));
                            
                            ssize_t bytes_received = readFromSocket(client_socket, ssl, temp_buffer, 
                                                                  to_read, use_ssl, logger);
                            
                            if (bytes_received <= 0) {
                                logger->log(LogLevel::ERROR, "Error reading request body");
                                conn_state.should_close = true;
                                break;
                            }
                            
                            request.body.append(temp_buffer, bytes_received);
                        }
                    } else {
                        request.body = request_buffer.substr(header_end, content_length);
                    }
                } catch (const std::exception& e) {
                    logger->log(LogLevel::WARNING, "Invalid Content-Length value");
                    conn_state.should_close = true;
                    break;
                }
            } else {
                auto te_it = request.headers.find("transfer-encoding");
                if (te_it != request.headers.end()) {
                    std::string te_value = te_it->second;
                    std::transform(te_value.begin(), te_value.end(), te_value.begin(), ::tolower);
                    
                    if (te_value.find("chunked") != std::string::npos) {
                        logger->log(LogLevel::DEBUG, "Reading chunked body");
                        size_t header_end = request_buffer.find("\r\n\r\n") + 4;
                        if (header_end < request_buffer.length()) {
                            request.body = request_buffer.substr(header_end);
                        }
                        std::string chunked_body = readChunkedBody(client_socket, ssl, use_ssl, logger, timeout);
                        request.body += chunked_body;
                    }
                }
            }
        }
        
        if (conn_state.should_close) {
            break;
        }
        
        // ===== LOG COMPLETE REQUEST =====
        logger->log(LogLevel::INFO, "===== COMPLETE REQUEST =====");
        logger->log(LogLevel::INFO, "Request Line: " + request.method + " " + request.path + " " + request.version);
        logger->log(LogLevel::INFO, "Headers:");
        for (const auto& header : request.headers) {
            logger->log(LogLevel::INFO, "  " + header.first + ": " + header.second);
        }
        if (!request.body.empty()) {
            logger->log(LogLevel::INFO, "Body (" + std::to_string(request.body.length()) + " bytes):");
            // Limit body logging to prevent huge logs
            if (request.body.length() <= 1024) {
                logger->log(LogLevel::INFO, request.body);
            } else {
                logger->log(LogLevel::INFO, request.body.substr(0, 1024) + "\n... (truncated, total " + 
                           std::to_string(request.body.length()) + " bytes)");
            }
        } else {
            logger->log(LogLevel::INFO, "Body: (empty)");
        }
        logger->log(LogLevel::INFO, "===========================");
        
        // NOW increment request counter AFTER we've made the keep-alive decision
        conn_state.requests_handled++;
        
        // Process request and prepare response
        logger->log(LogLevel::DEBUG, "Processing request...");
        std::map<std::string, std::string> response_headers;
        std::string response_body;
        int status_code = 200;
        
        // Add Connection header based on keep-alive decision
        if (keep_alive && !conn_state.should_close) {
            response_headers["Connection"] = "keep-alive";
            std::stringstream ka_header;
            ka_header << "timeout=" << ka_timeout_seconds;
            ka_header << ", max=" << (ka_max_requests - conn_state.requests_handled);
            response_headers["Keep-Alive"] = ka_header.str();
            logger->log(LogLevel::DEBUG, "Setting Keep-Alive header: " + ka_header.str());
        } else {
            response_headers["Connection"] = "close";
            conn_state.should_close = true;
        }
        
        // Step 1: Check authentication FIRST (except for auth routes)
        Auth::SessionInfo session_info = {false, 0, "", ""};
        std::string session_token;
        bool is_auth_route = (request.path.find("/auth/") == 0);
        bool is_file_route = (request.path.find("/files") == 0);
        auto cookie_it = request.headers.find("cookie");
        
        if (cookie_it != request.headers.end()) {
            session_token = auth_manager->extractSessionFromCookies(cookie_it->second);
        }
        
        if (!is_auth_route) 
        {
                bool should_redirect = false;

                // Check if session token exists and is valid
                if (!session_token.empty()) {
                    session_info = auth_manager->validateSession(session_token);
                    if (session_info.valid) {
                        logger->log(LogLevel::INFO, "Authenticated request from user: " + session_info.username);
                    } else {
                        logger->log(LogLevel::INFO, "Unauthorized file access attempt");
                        should_redirect = true;
                    }
                } else {
                    logger->log(LogLevel::INFO, "No session token provided for protected route");
                    should_redirect = true;
                }

                // Perform redirect if authentication failed
                if (should_redirect) {
                    std::string redirect_url = "/auth/login?redirect=" + urlEncode(request.path);
                    response_headers["Location"] = redirect_url;
                    response_headers["Content-Type"] = "text/html";

                    sendHttpResponse(
                        client_socket,
                        use_ssl,
                        ssl,
                        302,
                        response_headers,
                        "<html><body>Redirecting to login...</body></html>",
                        logger
                    );

                    if (conn_state.should_close) {
                        break;
                    }
                    continue;
                }
        }


        // Step 2: Handle authentication routes
        if (auth_manager && auth_routes && is_auth_route) {
            logger->log(LogLevel::DEBUG, "Handling auth route: " + request.path);
            
            try {
                std::string headers_str;
                for (const auto& header : request.headers) {
                    headers_str += header.first + ": " + header.second + "\r\n";
                }
                
                auto auth_response = auth_routes->handleRequest(request.method, request.path, 
                                                              headers_str, request.body);
                
                status_code = auth_response.status_code;
                response_body = auth_response.body;
                
                for (const auto& header : auth_response.headers) {
                    response_headers[header.first] = header.second;
                }
                
            } catch (const std::exception& e) {
                logger->log(LogLevel::ERROR, "Auth route error: " + std::string(e.what()));
                status_code = 500;
                response_headers["Content-Type"] = "application/json";
                response_body = R"({"error": "Internal server error"})";
                response_headers["Connection"] = "close";
                conn_state.should_close = true;
            }
            
            sendHttpResponse(client_socket, use_ssl, ssl, status_code, 
                           response_headers, response_body, logger);
            
            if (conn_state.should_close) {
                break;
            }
            continue;
        }

        // Step 3: Handle file management routes
        if (file_manager && file_routes && is_file_route) {
            logger->log(LogLevel::DEBUG, "Handling file management route: " + request.path);
            
            
            try {
                std::string headers_str;
                for (const auto& header : request.headers) {
                    headers_str += header.first + ": " + header.second + "\r\n";
                }
                
                auto file_response = file_routes->handleRequest(
                    request.method, request.path, headers_str, request.body, session_info
                );
                
                status_code = file_response.status_code;
                response_body = file_response.body;
                
                for (const auto& header : file_response.headers) {
                    response_headers[header.first] = header.second;
                }
                
            } catch (const std::exception& e) {
                logger->log(LogLevel::ERROR, "File route error: " + std::string(e.what()));
                status_code = 500;
                response_headers["Content-Type"] = "application/json";
                response_body = R"({"error": "Internal server error"})";
                response_headers["Connection"] = "close";
                conn_state.should_close = true;
            }
            
            sendHttpResponse(client_socket, use_ssl, ssl, status_code, 
                           response_headers, response_body, logger);
            
            if (conn_state.should_close) {
                break;
            }
            continue;
        }

        // Step 4: Handle authentication for regular routes
        if (auth_manager && !is_auth_route && !session_info.valid && isProtectedRoute(request.path)) {
            logger->log(LogLevel::INFO, "Unauthorized access attempt to: " + request.path);
            
            std::string html = R"(
                                <!DOCTYPE html>
                                <html>
                                <head>
                                    <title>401 Unauthorized</title>
                                    <style>
                                        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; 
                                            padding: 20px; text-align: center; }
                                        .error { background: #fee; color: #c00; padding: 30px; border-radius: 10px; }
                                        a { color: #007bff; text-decoration: none; }
                                        a:hover { text-decoration: underline; }
                                    </style>
                                </head>
                                <body>
                                    <div class="error">
                                        <h1>401 Unauthorized</h1>
                                        <p>You must be logged in to access this page.</p>
                                        <p><a href="/auth/login">Login</a> | <a href="/auth/register">Create Account</a></p>
                                    </div>
                                </body>
                                </html>
                                )";
            
            response_headers["Content-Type"] = "text/html";
            response_headers["WWW-Authenticate"] = "Cookie realm=\"Protected Area\"";
            sendHttpResponse(client_socket, use_ssl, ssl, 401, response_headers, html, logger);
            
            if (conn_state.should_close) {
                break;
            }
            continue;
        }
        
        // Step 5: Handle regular routes (with authentication already verified)
        logger->log(LogLevel::DEBUG, "Handling regular route...");
        bool route_found = false;
        
        if (request.path == "/dashboard" && session_info.valid) {
            logger->log(LogLevel::DEBUG, "Generating dashboard page");
            std::stringstream dashboard;
            dashboard << R"(
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <title>Dashboard</title>
                                <style>
                                    body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                                    .header { background: #007bff; color: white; padding: 20px; border-radius: 5px; 
                                            margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
                                    .info { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 15px; }
                                    .logout { background: #dc3545; color: white; padding: 10px 20px; 
                                            text-decoration: none; border-radius: 5px; border: none; cursor: pointer; }
                                    .nav { margin-bottom: 20px; }
                                    .nav a { margin-right: 20px; text-decoration: none; color: #007bff; }
                                    .feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
                                    .feature-card { background: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; }
                                    .feature-card h3 { color: #007bff; }
                                    .feature-card a { display: inline-block; margin-top: 10px; padding: 8px 16px; 
                                                    background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
                                    .feature-card a:hover { background: #0056b3; }
                                </style>
                            </head>
                            <body>
                                <div class="header">
                                    <h1>Welcome, )" << session_info.username << R"(!</h1>
                                    <button class="logout" onclick="logout()\">Logout</button>
                                </div>
                                <div class="nav">
                                    <a href="/">Home</a>
                                    <a href="/dashboard">Dashboard</a>
                                    <a href="/files">File Manager</a>
                                    <a href="/profile">Profile</a>
                                </div>
                                <div class="info">
                                    <h2>Account Information</h2>
                                    <p><strong>Username:</strong> )" << session_info.username << R"(</p>
                                    <p><strong>Email:</strong> )" << session_info.email << R"(</p>
                                    <p><strong>User ID:</strong> )" << session_info.user_id << R"(</p>
                                    <p><strong>Session Status:</strong> Active</p>
                                </div>
                                <div class="feature-grid">
                                    <div class="feature-card">
                                        <h3>📁 File Manager</h3>
                                        <p>Upload, download, and manage your files</p>
                                        <a href="/files">Open File Manager</a>
                                    </div>
                                    <div class="feature-card">
                                        <h3>👤 Profile</h3>
                                        <p>View and edit your profile information</p>
                                        <a href="/profile">View Profile</a>
                                    </div>
                                    <div class="feature-card">
                                        <h3>⚙️ Settings</h3>
                                        <p>Configure your account settings</p>
                                        <a href="/settings">Open Settings</a>
                                    </div>
                                </div>
                                
                                <script>
                                function logout() {
                                    fetch('/auth/logout', { 
                                        method: 'POST',
                                        credentials: 'same-origin'
                                    })
                                    .then(() => window.location.href = '/')
                                    .catch(err => alert('Logout failed: ' + err));
                                }
                                </script>
                            </body>
                            </html>
                            )";
            
            status_code = 200;
            response_headers["Content-Type"] = "text/html";
            response_body = dashboard.str();
            route_found = true;
        } else {
            for (const auto& route : config.routes) {
                if (route.path == request.path && route.method == request.method) {
                    route_found = true;
                    
                    std::string processed_body;
                    std::string local_file = config.home_folder + route.local_file;
                    logger->log(LogLevel::DEBUG, "Found matching route: " + route.path + " -> " + local_file);

                    load_html(local_file, response_headers, processed_body);
                    
                    if (session_info.valid) {
                        size_t pos = 0;
                        while ((pos = processed_body.find("{{username}}", pos)) != std::string::npos) {
                            processed_body.replace(pos, 12, session_info.username);
                            pos += session_info.username.length();
                        }
                        
                        pos = 0;
                        while ((pos = processed_body.find("{{email}}", pos)) != std::string::npos) {
                            processed_body.replace(pos, 9, session_info.email);
                            pos += session_info.email.length();
                        }
                    }
                    
                    response_body = processed_body;
                    break;
                }
            }
        }
        
        if (!route_found) {
            logger->log(LogLevel::DEBUG, "Route not found, handling static file request");
            handleHttpRequest(request.path, config.home_folder, client_socket);
            
            if (conn_state.should_close) {
                break;
            }
            continue;
        }
        
        sendHttpResponse(client_socket, use_ssl, ssl, status_code, 
                       response_headers, response_body, logger);
        
        if (conn_state.should_close) {
            break;
        }
        
        logger->log(LogLevel::DEBUG, "Keep-alive connection ready for next request (handled: " + 
                    std::to_string(conn_state.requests_handled) + "/" + std::to_string(ka_max_requests) + ")");
    }
    
    logger->log(LogLevel::DEBUG, "Closing connection after " + 
                std::to_string(conn_state.requests_handled) + " requests");
    
    if (use_ssl && ssl) {
        int shutdown_result = SSL_shutdown(ssl);
        if (shutdown_result == 0) {
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
    }
    close(client_socket);
    
    logger->log(LogLevel::DEBUG, "<<< Exiting handle_client()");
}

void handle_client_old(SSL_CTX* ctx, const ServerConfig& config, int client_socket, 
                  Logger* logger, const std::unordered_map<std::string, std::string>& mime_types,
                  Auth::AuthManager* auth_manager, AuthRoutes::RouteHandler* auth_routes,
                  bool use_ssl = true) {
    logger->log(LogLevel::DEBUG, ">>> Entering handle_client() - client_socket: " + std::to_string(client_socket) + 
                ", use_ssl: " + std::to_string(use_ssl));
    
    SSL* ssl = nullptr;
    
    // Connection state for keep-alive
    struct ConnectionState {
        int requests_handled = 0;
        bool should_close = false;
        std::chrono::steady_clock::time_point last_activity;
    } conn_state;
    
    // Keep-alive configuration
    bool ka_enabled = config.keepalive.enabled;
    int ka_max_requests = config.keepalive.max_requests;
    int ka_timeout_seconds = config.keepalive.timeout;
    
    // Set socket to blocking mode
    int flags = fcntl(client_socket, F_GETFL, 0);
    if (flags != -1) {
        fcntl(client_socket, F_SETFL, flags & ~O_NONBLOCK);
    }
    
    // SSL handshake for HTTPS connections
    if (use_ssl) {
        ssl = SSL_new(ctx);
        if (!ssl) {
            logger->log(LogLevel::ERROR, "Failed to create SSL object");
            close(client_socket);
            logger->log(LogLevel::DEBUG, "<<< Exiting handle_client() - SSL creation failed");
            return;
        }

        if (!SSL_set_fd(ssl, client_socket)) {
            logger->log(LogLevel::ERROR, "Failed to set file descriptor for SSL");
            SSL_free(ssl);
            close(client_socket);
            logger->log(LogLevel::DEBUG, "<<< Exiting handle_client() - SSL_set_fd failed");
            return;
        }

        int handshake_result = SSL_accept(ssl);
        if (handshake_result <= 0) {
            int ssl_error = SSL_get_error(ssl, handshake_result);
            logger->log(LogLevel::ERROR, "SSL handshake failed with error: " + std::to_string(ssl_error));
            if (ssl_error == SSL_ERROR_SSL) {
                char err_buf[256];
                ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
                logger->log(LogLevel::ERROR, "SSL error details: " + std::string(err_buf));
            }
            SSL_free(ssl);
            close(client_socket);
            logger->log(LogLevel::DEBUG, "<<< Exiting handle_client() - SSL handshake failed");
            return;
        }
        
        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
        if (cipher) {
            logger->log(LogLevel::DEBUG, "SSL handshake successful, cipher: " + 
                       std::string(SSL_CIPHER_get_name(cipher)));
        }
    }

    // Keep-alive loop - handle multiple requests on same connection
    while (!conn_state.should_close && g_running.load()) {
        conn_state.last_activity = std::chrono::steady_clock::now();
        
        // Set socket timeout based on whether we've already handled requests
        struct timeval timeout;
        if (conn_state.requests_handled > 0) {
            timeout.tv_sec = ka_timeout_seconds;
            logger->log(LogLevel::DEBUG, "Setting keep-alive timeout: " + std::to_string(ka_timeout_seconds) + " seconds");
        } else {
            timeout.tv_sec = config.timeout;
            logger->log(LogLevel::DEBUG, "Setting initial timeout: " + std::to_string(config.timeout) + " seconds");
        }
        timeout.tv_usec = 0;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        // Read HTTP request headers
        std::string request_buffer;
        char temp_buffer[4096];
        bool headers_complete = false;
        const size_t max_header_size = 8192;
        
        // Phase 1: Read headers
        logger->log(LogLevel::DEBUG, "Reading request headers for request #" + 
                    std::to_string(conn_state.requests_handled + 1) + "...");
        
        while (!headers_complete) {
            ssize_t bytes_received = readFromSocket(client_socket, ssl, temp_buffer, 
                                                  sizeof(temp_buffer) - 1, use_ssl, logger);
            
            if (bytes_received <= 0) {
                if (bytes_received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (conn_state.requests_handled > 0) {
                        logger->log(LogLevel::DEBUG, "Keep-alive timeout after " + 
                                   std::to_string(conn_state.requests_handled) + " requests");
                    } else {
                        logger->log(LogLevel::WARNING, "Socket timeout on first request");
                    }
                } else if (bytes_received == 0) {
                    if (conn_state.requests_handled > 0) {
                        logger->log(LogLevel::DEBUG, "Client closed keep-alive connection after " + 
                                   std::to_string(conn_state.requests_handled) + " requests");
                    } else {
                        logger->log(LogLevel::DEBUG, "Client closed connection before sending request");
                    }
                }
                conn_state.should_close = true;
                break;
            }
            
            temp_buffer[bytes_received] = '\0';
            request_buffer.append(temp_buffer, bytes_received);
            
            size_t header_end = request_buffer.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                headers_complete = true;
            }
            
            if (request_buffer.size() > max_header_size) {
                logger->log(LogLevel::WARNING, "Request headers too large");
                std::map<std::string, std::string> error_headers = {
                    {"Content-Type", "text/plain"},
                    {"Connection", "close"}
                };
                sendHttpResponse(client_socket, use_ssl, ssl, 413, error_headers, 
                               "Request header too large", logger);
                conn_state.should_close = true;
                break;
            }
        }
        
        if (conn_state.should_close) {
            break;
        }
        
        // Parse the request headers
        logger->log(LogLevel::DEBUG, "Parsing HTTP request...");
        HttpRequest request = parseHttpRequest(request_buffer);
        if (!request.complete) {
            logger->log(LogLevel::WARNING, "Failed to parse HTTP request");
            std::map<std::string, std::string> error_headers = {
                {"Content-Type", "text/plain"},
                {"Connection", "close"}
            };
            sendHttpResponse(client_socket, use_ssl, ssl, 400, error_headers, 
                           "Bad Request", logger);
            conn_state.should_close = true;
            break;
        }
        
        // Log the request
        logger->log(LogLevel::DEBUG, "Request #" + std::to_string(conn_state.requests_handled + 1) + 
                    ": " + request.method + " " + request.path);
        
        // Determine if we should keep connection alive BEFORE incrementing the counter
        bool keep_alive = false;
        if (ka_enabled && (conn_state.requests_handled + 1) < ka_max_requests) {
            auto conn_it = request.headers.find("connection");
            if (conn_it != request.headers.end()) {
                std::string conn_value = conn_it->second;
                std::transform(conn_value.begin(), conn_value.end(), conn_value.begin(), ::tolower);
                
                if (conn_value.find("close") != std::string::npos) {
                    keep_alive = false;
                    conn_state.should_close = true;
                    logger->log(LogLevel::DEBUG, "Client requested connection close");
                } else if (conn_value.find("keep-alive") != std::string::npos) {
                    keep_alive = true;
                }
            } else {
                // Default behavior based on HTTP version
                keep_alive = (request.version == "HTTP/1.1");
            }
            
            logger->log(LogLevel::DEBUG, "Keep-alive decision: " + std::string(keep_alive ? "true" : "false") + 
                       " (requests handled: " + std::to_string(conn_state.requests_handled) + 
                       ", max: " + std::to_string(ka_max_requests) + ")");
        } else {
            conn_state.should_close = true;
            logger->log(LogLevel::DEBUG, "Keep-alive disabled or max requests reached");
        }
        
        // Phase 2: Read body if needed
        bool has_body = shouldHaveBody(request.method, request.headers);
        
        if (has_body) {
            logger->log(LogLevel::DEBUG, "Reading request body...");
            auto cl_it = request.headers.find("content-length");
            if (cl_it != request.headers.end()) {
                try {
                    size_t content_length = std::stoull(cl_it->second);
                    
                    if (content_length > 10 * 1024 * 1024) {
                        logger->log(LogLevel::WARNING, "Content-Length too large: " + std::to_string(content_length));
                        std::map<std::string, std::string> error_headers = {
                            {"Content-Type", "text/plain"},
                            {"Connection", "close"}
                        };
                        sendHttpResponse(client_socket, use_ssl, ssl, 413, error_headers, 
                                       "Request body too large", logger);
                        conn_state.should_close = true;
                        break;
                    }
                    
                    size_t header_end = request_buffer.find("\r\n\r\n") + 4;
                    size_t current_body_size = request_buffer.length() - header_end;
                    
                    if (current_body_size < content_length) {
                        request.body = request_buffer.substr(header_end);
                        
                        while (request.body.length() < content_length) {
                            size_t remaining = content_length - request.body.length();
                            size_t to_read = std::min(remaining, sizeof(temp_buffer));
                            
                            ssize_t bytes_received = readFromSocket(client_socket, ssl, temp_buffer, 
                                                                  to_read, use_ssl, logger);
                            
                            if (bytes_received <= 0) {
                                logger->log(LogLevel::ERROR, "Error reading request body");
                                conn_state.should_close = true;
                                break;
                            }
                            
                            request.body.append(temp_buffer, bytes_received);
                        }
                    } else {
                        request.body = request_buffer.substr(header_end, content_length);
                    }
                } catch (const std::exception& e) {
                    logger->log(LogLevel::WARNING, "Invalid Content-Length value");
                    conn_state.should_close = true;
                    break;
                }
            } else {
                auto te_it = request.headers.find("transfer-encoding");
                if (te_it != request.headers.end()) {
                    std::string te_value = te_it->second;
                    std::transform(te_value.begin(), te_value.end(), te_value.begin(), ::tolower);
                    
                    if (te_value.find("chunked") != std::string::npos) {
                        logger->log(LogLevel::DEBUG, "Reading chunked body");
                        size_t header_end = request_buffer.find("\r\n\r\n") + 4;
                        if (header_end < request_buffer.length()) {
                            request.body = request_buffer.substr(header_end);
                        }
                        std::string chunked_body = readChunkedBody(client_socket, ssl, use_ssl, logger, timeout);
                        request.body += chunked_body;
                    }
                }
            }
        }
        
        if (conn_state.should_close) {
            break;
        }
        
        // ===== LOG COMPLETE REQUEST =====
        logger->log(LogLevel::INFO, "===== COMPLETE REQUEST =====");
        logger->log(LogLevel::INFO, "Request Line: " + request.method + " " + request.path + " " + request.version);
        logger->log(LogLevel::INFO, "Headers:");
        for (const auto& header : request.headers) {
            logger->log(LogLevel::INFO, "  " + header.first + ": " + header.second);
        }
        if (!request.body.empty()) {
            logger->log(LogLevel::INFO, "Body (" + std::to_string(request.body.length()) + " bytes):");
            // Limit body logging to prevent huge logs
            if (request.body.length() <= 1024) {
                logger->log(LogLevel::INFO, request.body);
            } else {
                logger->log(LogLevel::INFO, request.body.substr(0, 1024) + "\n... (truncated, total " + 
                           std::to_string(request.body.length()) + " bytes)");
            }
        } else {
            logger->log(LogLevel::INFO, "Body: (empty)");
        }
        logger->log(LogLevel::INFO, "===========================");
        
        // NOW increment request counter AFTER we've made the keep-alive decision
        conn_state.requests_handled++;
        
        // Process request and prepare response
        logger->log(LogLevel::DEBUG, "Processing request...");
        std::map<std::string, std::string> response_headers;
        std::string response_body;
        int status_code = 200;
        
        // Add Connection header based on keep-alive decision
        if (keep_alive && !conn_state.should_close) {
            response_headers["Connection"] = "keep-alive";
            std::stringstream ka_header;
            ka_header << "timeout=" << ka_timeout_seconds;
            ka_header << ", max=" << (ka_max_requests - conn_state.requests_handled);
            response_headers["Keep-Alive"] = ka_header.str();
            logger->log(LogLevel::DEBUG, "Setting Keep-Alive header: " + ka_header.str());
        } else {
            response_headers["Connection"] = "close";
            conn_state.should_close = true;
        }
        
        // Step 1: Check authentication FIRST (except for auth routes)
        Auth::SessionInfo session_info = {false, 0, "", ""};
        std::string session_token;
        bool is_auth_route = (request.path.find("/auth/") == 0);
        auto cookie_it = request.headers.find("cookie");
        
        if (cookie_it != request.headers.end()) 
        {
                session_token = auth_manager->extractSessionFromCookies(cookie_it->second);
        }
        
        if (!session_token.empty()) {
                session_info = auth_manager->validateSession(session_token);
                if (session_info.valid) {
                    logger->log(LogLevel::DEBUG, "Authenticated request from user: " + session_info.username);
                }
        }

        // Step 1: Handle authentication routes
        if (auth_manager && auth_routes && is_auth_route) {
            logger->log(LogLevel::DEBUG, "Handling auth route: " + request.path);
            
            try {
                std::string headers_str;
                for (const auto& header : request.headers) {
                    headers_str += header.first + ": " + header.second + "\r\n";
                }
                
                auto auth_response = auth_routes->handleRequest(request.method, request.path, 
                                                              headers_str, request.body);
                
                status_code = auth_response.status_code;
                response_body = auth_response.body;
                
                for (const auto& header : auth_response.headers) {
                    response_headers[header.first] = header.second;
                }
                
            } catch (const std::exception& e) {
                logger->log(LogLevel::ERROR, "Auth route error: " + std::string(e.what()));
                status_code = 500;
                response_headers["Content-Type"] = "application/json";
                response_body = R"({"error": "Internal server error"})";
                response_headers["Connection"] = "close";
                conn_state.should_close = true;
            }
            
            sendHttpResponse(client_socket, use_ssl, ssl, status_code, 
                           response_headers, response_body, logger);
            
            if (conn_state.should_close) {
                break;
            }
            continue;
        }

        // Step 2: Handle authentication for regular routes
        if (auth_manager && !is_auth_route && !session_info.valid) {
                logger->log(LogLevel::INFO, "Unauthorized access attempt to: " + request.path);
                
                std::string html = R"(
                                    <!DOCTYPE html>
                                    <html>
                                    <head>
                                        <title>401 Unauthorized</title>
                                        <style>
                                            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; 
                                                padding: 20px; text-align: center; }
                                            .error { background: #fee; color: #c00; padding: 30px; border-radius: 10px; }
                                            a { color: #007bff; text-decoration: none; }
                                            a:hover { text-decoration: underline; }
                                        </style>
                                    </head>
                                    <body>
                                        <div class="error">
                                            <h1>401 Unauthorized</h1>
                                            <p>You must be logged in to access this page.</p>
                                            <p><a href="/auth/login">Login</a> | <a href="/auth/register">Create Account</a></p>
                                        </div>
                                    </body>
                                    </html>
                                    )";
                
                response_headers["Content-Type"] = "text/html";
                response_headers["WWW-Authenticate"] = "Cookie realm=\"Protected Area\"";
                sendHttpResponse(client_socket, use_ssl, ssl, 401, response_headers, html, logger);
                
                if (conn_state.should_close) {
                    break;
                }
                continue;
            }

        
        // Step 3: Handle regular routes (with authentication already verified)
        logger->log(LogLevel::DEBUG, "Handling regular route...");
        bool route_found = false;
        
        if (request.path == "/dashboard" && session_info.valid) {
            logger->log(LogLevel::DEBUG, "Generating dashboard page");
            std::stringstream dashboard;
            dashboard << R"(
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <title>Dashboard</title>
                                <style>
                                    body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                                    .header { background: #007bff; color: white; padding: 20px; border-radius: 5px; 
                                            margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
                                    .info { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 15px; }
                                    .logout { background: #dc3545; color: white; padding: 10px 20px; 
                                            text-decoration: none; border-radius: 5px; border: none; cursor: pointer; }
                                    .nav { margin-bottom: 20px; }
                                    .nav a { margin-right: 20px; text-decoration: none; color: #007bff; }
                                </style>
                            </head>
                            <body>
                                <div class="header">
                                    <h1>Welcome, )" << session_info.username << R"(!</h1>
                                    <button class="logout" onclick="logout()\">Logout</button>
                                </div>
                                <div class="nav">
                                    <a href="/">Home</a>
                                    <a href="/dashboard">Dashboard</a>
                                    <a href="/profile">Profile</a>
                                </div>
                                <div class="info">
                                    <h2>Account Information</h2>
                                    <p><strong>Username:</strong> )" << session_info.username << R"(</p>
                                    <p><strong>Email:</strong> )" << session_info.email << R"(</p>
                                    <p><strong>User ID:</strong> )" << session_info.user_id << R"(</p>
                                    <p><strong>Session Status:</strong> Active</p>
                                </div>
                                <div class="info">
                                    <h2>Quick Actions</h2>
                                    <p>This is your personal dashboard. Add your content here!</p>
                                </div>
                                
                                <script>
                                function logout() {
                                    fetch('/auth/logout', { 
                                        method: 'POST',
                                        credentials: 'same-origin'
                                    })
                                    .then(() => window.location.href = '/')
                                    .catch(err => alert('Logout failed: ' + err));
                                }
                                </script>
                            </body>
                            </html>
                            )";
            
            status_code = 200;
            response_headers["Content-Type"] = "text/html";
            response_body = dashboard.str();
            route_found = true;
        } else {
            for (const auto& route : config.routes) {
                if (route.path == request.path && route.method == request.method) {
                    route_found = true;
                    
                    std::string processed_body;
                    std::string local_file = config.home_folder + route.local_file;
                    logger->log(LogLevel::DEBUG, "Found matching route: " + route.path + " -> " + local_file);

                    load_html(local_file, response_headers, processed_body);
                    
                    if (session_info.valid) {
                        size_t pos = 0;
                        while ((pos = processed_body.find("{{username}}", pos)) != std::string::npos) {
                            processed_body.replace(pos, 12, session_info.username);
                            pos += session_info.username.length();
                        }
                        
                        pos = 0;
                        while ((pos = processed_body.find("{{email}}", pos)) != std::string::npos) {
                            processed_body.replace(pos, 9, session_info.email);
                            pos += session_info.email.length();
                        }
                    }
                    
                    response_body = processed_body;
                    break;
                }
            }
        }
        
        if (!route_found) {
            logger->log(LogLevel::DEBUG, "Route not found, handling static file request");
            handleHttpRequest(request.path, config.home_folder, client_socket);
        }
        
        sendHttpResponse(client_socket, use_ssl, ssl, status_code, 
                       response_headers, response_body, logger);
        
        if (conn_state.should_close) {
            break;
        }
        
        logger->log(LogLevel::DEBUG, "Keep-alive connection ready for next request (handled: " + 
                    std::to_string(conn_state.requests_handled) + "/" + std::to_string(ka_max_requests) + ")");
    }
    
    logger->log(LogLevel::DEBUG, "Closing connection after " + 
                std::to_string(conn_state.requests_handled) + " requests");
    
    if (use_ssl && ssl) {
        int shutdown_result = SSL_shutdown(ssl);
        if (shutdown_result == 0) {
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
    }
    close(client_socket);
    
    logger->log(LogLevel::DEBUG, "<<< Exiting handle_client()");
}

int main(int argc, char* argv[]) {
    std::string config_path = "config.json";
    if (argc > 1) {
        config_path = argv[1];
    }

    ServerConfig config;
    try {
        config = parse_config(config_path);
    } catch (const std::exception& ex) {
        std::cerr << "Error parsing config: " << ex.what() << std::endl;
        return 1;
    }

    // Initialize logger
    logger = std::make_unique<Logger>(config.logging.console_output);
    logger->Config(config.logging.file);
    logger->set_level(config.logging.level);

    logger->log(LogLevel::INFO, "Server starting...");
    logger->log(LogLevel::DEBUG, ">>> Entering main()");

    // Initialize authentication if enabled
    std::unique_ptr<Auth::AuthManager> auth_manager;
    std::unique_ptr<AuthRoutes::RouteHandler> auth_routes;
    std::unique_ptr<FileManager::UserFileManager> file_manager;
    std::unique_ptr<FileRoutes::FileRouteHandler> file_routes;
    
    if (config.authentication.enabled) {
        logger->log(LogLevel::INFO, "Initializing authentication system...");
        
        try {
            // Configure authentication
            Auth::AuthConfig auth_config;
            auth_config.database_path = config.authentication.database_path;
            auth_config.session_lifetime = config.authentication.session_lifetime;
            auth_config.extend_session_on_activity = config.authentication.extend_session_on_activity;
            auth_config.smtp_server = config.authentication.smtp.server;
            auth_config.smtp_username = config.authentication.smtp.username;
            auth_config.smtp_password = config.authentication.smtp.password;
            auth_config.smtp_from = config.authentication.smtp.from;
            auth_config.create_user_folders = true;  // Enable user folder creation
            auth_config.user_storage_path = config.home_folder + "/user_storage";
            
            // Create authentication components
            auth_manager = std::make_unique<Auth::AuthManager>(auth_config, logger.get());
            auth_routes = std::make_unique<AuthRoutes::RouteHandler>(auth_manager.get(), logger.get(), config.home_folder);
            
            logger->log(LogLevel::INFO, "Authentication system initialized successfully");
            
            // Initialize file management system
            logger->log(LogLevel::INFO, "Initializing file management system...");
            
            try {
                // Create user storage directory if it doesn't exist
                std::string user_storage_path = config.home_folder + "/user_storage";
                if (!fs::exists(user_storage_path)) {
                    fs::create_directories(user_storage_path);
                    logger->log(LogLevel::INFO, "Created user storage directory: " + user_storage_path);
                }
                
                file_manager = std::make_unique<FileManager::UserFileManager>(user_storage_path, logger.get());
                file_routes = std::make_unique<FileRoutes::FileRouteHandler>(
                    file_manager.get(), auth_manager.get(), logger.get()
                );
                
                logger->log(LogLevel::INFO, "File management system initialized successfully");
            } catch (const std::exception& e) {
                logger->log(LogLevel::ERROR, "Failed to initialize file management: " + std::string(e.what()));
                // Continue without file management
            }
            
        } catch (const std::exception& e) {
            logger->log(LogLevel::ERROR, "Failed to initialize authentication: " + std::string(e.what()));
            logger->log(LogLevel::DEBUG, "<<< Exiting main() - auth init failed");
            return 1;
        }
    } else {
        logger->log(LogLevel::INFO, "Authentication system disabled");
    }

    // Initialize SSL
    logger->log(LogLevel::DEBUG, "Initializing SSL...");
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        logger->log(LogLevel::ERROR, "Failed to create SSL context");
        logger->log(LogLevel::DEBUG, "<<< Exiting main() - SSL context failed");
        return 1;
    }

    // Configure SSL context
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    
    if (SSL_CTX_use_certificate_file(ctx, config.ssl.cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        logger->log(LogLevel::ERROR, "Failed to load certificate");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        logger->log(LogLevel::DEBUG, "<<< Exiting main() - certificate load failed");
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, config.ssl.key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        logger->log(LogLevel::ERROR, "Failed to load private key");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        logger->log(LogLevel::DEBUG, "<<< Exiting main() - private key load failed");
        return 1;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        logger->log(LogLevel::ERROR, "Private key does not match certificate");
        SSL_CTX_free(ctx);
        logger->log(LogLevel::DEBUG, "<<< Exiting main() - key/cert mismatch");
        return 1;
    }

    // Initialize MIME types
    std::unordered_map<std::string, std::string> mime_types = {
        {"html", "text/html"},
        {"htm",  "text/html"},
        {"css",  "text/css"},
        {"js",   "application/javascript"},
        {"json", "application/json"},
        {"png",  "image/png"},
        {"jpg",  "image/jpeg"},
        {"jpeg", "image/jpeg"},
        {"gif",  "image/gif"},
        {"svg",  "image/svg+xml"},
        {"ico",  "image/x-icon"},
        {"txt",  "text/plain"},
        {"pdf",  "application/pdf"},
        {"xml",  "application/xml"}
    };

    // Create HTTPS server socket
    int https_socket = create_server_socket(config.host, config.port, logger.get());
    if (https_socket == -1) {
        SSL_CTX_free(ctx);
        logger->log(LogLevel::DEBUG, "<<< Exiting main() - HTTPS socket failed");
        return 1;
    }
    logger->log(LogLevel::INFO, "HTTPS server listening on " + config.host + ":" + std::to_string(config.port));

    // Create HTTP server socket if enabled
    int http_socket = -1;
    if (config.enable_http) {
        http_socket = create_server_socket(config.host, config.http_port, logger.get());
        if (http_socket == -1) {
            close(https_socket);
            SSL_CTX_free(ctx);
            logger->log(LogLevel::DEBUG, "<<< Exiting main() - HTTP socket failed");
            return 1;
        }
        logger->log(LogLevel::INFO, "HTTP server listening on " + config.host + ":" + std::to_string(config.http_port));
    }

    // Create thread pool
    logger->log(LogLevel::DEBUG, "Creating thread pool with " + std::to_string(config.threads) + " threads");
    ThreadPool pool(config.threads);

    // Handle SIGINT/SIGTERM
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // Set up poll structures
    std::vector<struct pollfd> poll_fds;
    poll_fds.push_back({https_socket, POLLIN, 0});
    if (config.enable_http) {
        poll_fds.push_back({http_socket, POLLIN, 0});
    }

    logger->log(LogLevel::INFO, "Server ready to accept connections");
    if (config.authentication.enabled) {
        logger->log(LogLevel::INFO, "Authentication endpoints available at /auth");
        if (file_manager && file_routes) {
            logger->log(LogLevel::INFO, "File management available at /files");
        }
    }

    // Accept loop
    logger->log(LogLevel::DEBUG, "Entering main accept loop");
    while (g_running.load()) {
        int poll_result = poll(poll_fds.data(), poll_fds.size(), 100);
        
        if (poll_result < 0) {
            if (errno == EINTR) continue;
            logger->log(LogLevel::ERROR, "Poll failed: " + std::string(strerror(errno)));
            break;
        }
        
        if (poll_result == 0) continue;
        
        for (size_t i = 0; i < poll_fds.size(); ++i) {
            if (poll_fds[i].revents & POLLIN) {
                sockaddr_in client_addr;
                socklen_t client_addr_len = sizeof(client_addr);
                int client_socket = accept(poll_fds[i].fd, (struct sockaddr*)&client_addr, &client_addr_len);
                
                if (client_socket < 0) {
                    if (errno == EWOULDBLOCK || errno == EAGAIN) {
                        continue;
                    }
                    logger->log(LogLevel::ERROR, "Accept failed: " + std::string(strerror(errno)));
                    continue;
                }

                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                
                bool is_https = (poll_fds[i].fd == https_socket);
                logger->log(LogLevel::INFO, "New " + std::string(is_https ? "HTTPS" : "HTTP") + 
                           " connection from " + std::string(client_ip));

                // Handle client in thread pool with authentication and file management
                pool.enqueue([ctx, config, client_socket, &logger, &mime_types, &auth_manager, &auth_routes, &file_manager, &file_routes, is_https]() {
                    handle_client(ctx, config, client_socket, logger.get(), mime_types, 
                                auth_manager.get(), auth_routes.get(), file_manager.get(), file_routes.get(), is_https);
                });
            }
        }
    }

    // Cleanup
    logger->log(LogLevel::INFO, "Shutting down server...");
    logger->log(LogLevel::DEBUG, "Closing sockets...");
    close(https_socket);
    if (http_socket != -1) {
        close(http_socket);
    }
    SSL_CTX_free(ctx);
    EVP_cleanup();
    logger->log(LogLevel::INFO, "Server shutdown complete");
    logger->log(LogLevel::DEBUG, "<<< Exiting main()");
    
    return 0;
}