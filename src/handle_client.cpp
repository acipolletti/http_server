// Complete handle_client function with authentication integration
// This replaces the handle_client function in server.cpp

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
#include "common.h"
#include "auth.hpp"
#include "auth_routes.hpp"

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
        "/static/",  // Static files
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

// Helper function to send HTTP response
void sendHttpResponse(int client_socket, bool use_ssl, SSL* ssl,
                     int status_code, const std::map<std::string, std::string>& headers,
                     const std::string& body) {
    std::string response = "HTTP/1.1 " + std::to_string(status_code);
    
    // Add status text
    switch(status_code) {
        case 200: response += " OK"; break;
        case 301: response += " Moved Permanently"; break;
        case 400: response += " Bad Request"; break;
        case 401: response += " Unauthorized"; break;
        case 403: response += " Forbidden"; break;
        case 404: response += " Not Found"; break;
        case 500: response += " Internal Server Error"; break;
        default: response += " OK"; break;
    }
    response += "\r\n";
    
    // Add headers
    for (const auto& header : headers) {
        response += header.first + ": " + header.second + "\r\n";
    }
    
    // Add content length if not present
    if (headers.find("Content-Length") == headers.end()) {
        response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    
    // Add security headers
    response += "X-Content-Type-Options: nosniff\r\n";
    response += "X-Frame-Options: DENY\r\n";
    
    response += "\r\n";
    response += body;
    
    // Send response
    if (use_ssl && ssl) {
        SSL_write(ssl, response.c_str(), response.size());
    } else {
        send(client_socket, response.c_str(), response.size(), MSG_NOSIGNAL);
    }
}

// Complete handle_client function with authentication
void handle_client(SSL_CTX* ctx, const ServerConfig& config, int client_socket, 
                  Logger* logger, const std::unordered_map<std::string, std::string>& mime_types,
                  Auth::AuthManager* auth_manager, AuthRoutes::RouteHandler* auth_routes,
                  bool use_ssl = true) {
    SSL* ssl = nullptr;
    
    // SSL handshake for HTTPS connections
    if (use_ssl) {
        ssl = SSL_new(ctx);
        if (!ssl) {
            logger->log(LogLevel::ERROR, "Failed to create SSL object");
            close(client_socket);
            return;
        }

        if (!SSL_set_fd(ssl, client_socket)) {
            logger->log(LogLevel::ERROR, "Failed to set file descriptor for SSL");
            SSL_free(ssl);
            close(client_socket);
            return;
        }

        if (SSL_accept(ssl) <= 0) {
            logger->log(LogLevel::ERROR, "SSL handshake failed");
            SSL_free(ssl);
            close(client_socket);
            return;
        }
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = config.timeout;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    // Read HTTP request
    char buffer[8192];  // Increased buffer size for larger requests
    int bytes_received;
    
    if (use_ssl) {
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    } else {
        bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    }
    
    if (bytes_received <= 0) {
        logger->log(LogLevel::ERROR, "Error receiving data");
        if (use_ssl && ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(client_socket);
        return;
    }

    buffer[bytes_received] = '\0';
    std::string request(buffer);

    // Parse HTTP request
    size_t header_end = request.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        logger->log(LogLevel::WARNING, "Invalid HTTP request - no header end found");
        if (use_ssl && ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(client_socket);
        return;
    }

    std::string headers = request.substr(0, header_end);
    std::string body = request.substr(header_end + 4);

    // Parse request line
    size_t method_end = headers.find(' ');
    if (method_end == std::string::npos) {
        logger->log(LogLevel::WARNING, "Invalid HTTP request - no method");
        if (use_ssl && ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(client_socket);
        return;
    }

    size_t path_end = headers.find(' ', method_end + 1);
    if (path_end == std::string::npos) {
        logger->log(LogLevel::WARNING, "Invalid HTTP request - no path");
        if (use_ssl && ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(client_socket);
        return;
    }

    std::string method = headers.substr(0, method_end);
    std::string path = headers.substr(method_end + 1, path_end - method_end - 1);
    
    // Remove query string from path if present
    size_t query_pos = path.find('?');
    if (query_pos != std::string::npos) {
        path = path.substr(0, query_pos);
    }

    // Log request
    logger->log(LogLevel::DEBUG, "Request: " + method + " " + path + " (" + 
                (use_ssl ? "HTTPS" : "HTTP") + ")");

    // Step 1: Check if this is an authentication route
    if (path.find("/auth/") == 0) {
        logger->log(LogLevel::DEBUG, "Handling auth route: " + path);
        
        try {
            auto auth_response = auth_routes->handleRequest(method, path, headers, body);
            
            // Send auth response
            sendHttpResponse(client_socket, use_ssl, ssl, 
                           auth_response.status_code, 
                           auth_response.headers, 
                           auth_response.body);
            
        } catch (const std::exception& e) {
            logger->log(LogLevel::ERROR, "Auth route error: " + std::string(e.what()));
            
            // Send error response
            std::map<std::string, std::string> error_headers = {
                {"Content-Type", "application/json"}
            };
            std::string error_body = R"({"error": "Internal server error"})";
            sendHttpResponse(client_socket, use_ssl, ssl, 500, error_headers, error_body);
        }
        
        // Cleanup and return
        if (use_ssl && ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(client_socket);
        return;
    }

    // Step 2: Check authentication for protected routes
    Auth::SessionInfo session_info = {false, 0, "", ""};
    std::string session_token;
    
    // Extract session cookie
    size_t cookie_pos = headers.find("Cookie:");
    if (cookie_pos != std::string::npos) {
        size_t cookie_start = cookie_pos + 7;
        size_t cookie_end = headers.find("\r\n", cookie_start);
        if (cookie_end != std::string::npos) {
            std::string cookie_header = headers.substr(cookie_start, cookie_end - cookie_start);
            session_token = auth_manager->extractSessionFromCookies(cookie_header);
        }
    }
    
    // Validate session if token found
    if (!session_token.empty()) {
        session_info = auth_manager->validateSession(session_token);
        if (session_info.valid) {
            logger->log(LogLevel::DEBUG, "Authenticated request from user: " + session_info.username);
        }
    }
    
    // Check if route requires authentication
    if (isProtectedRoute(path) && !session_info.valid) {
        logger->log(LogLevel::INFO, "Unauthorized access attempt to: " + path);
        
        // Send 401 Unauthorized response
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
        
        std::map<std::string, std::string> headers = {
            {"Content-Type", "text/html"},
            {"WWW-Authenticate", "Cookie realm=\"Protected Area\""}
        };
        
        sendHttpResponse(client_socket, use_ssl, ssl, 401, headers, html);
        
        // Cleanup
        if (use_ssl && ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(client_socket);
        return;
    }

    // Step 3: Handle regular routes (user is authenticated if required)
    bool route_found = false;
    json response_json;
    
    // Special handling for dashboard and other dynamic routes
    if (path == "/dashboard" && session_info.valid) {
        // Generate personalized dashboard
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
        <button class="logout" onclick="logout()">Logout</button>
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
        
        response_json = {
            {"status", 200},
            {"headers", {
                {"Content-Type", "text/html"},
                {"Content-Length", std::to_string(dashboard.str().size())}
            }},
            {"body", dashboard.str()}
        };
        route_found = true;
    } else {
        // Check configured routes
        for (const auto& route : config.routes) {
            if (route.path == path && route.method == method) {
                route_found = true;
                
                // Process template variables if user is authenticated
                std::string processed_body = route.response.body;
                if (session_info.valid) {
                    // Replace {{username}} with actual username
                    size_t pos = 0;
                    while ((pos = processed_body.find("{{username}}", pos)) != std::string::npos) {
                        processed_body.replace(pos, 12, session_info.username);
                        pos += session_info.username.length();
                    }
                    
                    // Replace {{email}} with actual email
                    pos = 0;
                    while ((pos = processed_body.find("{{email}}", pos)) != std::string::npos) {
                        processed_body.replace(pos, 9, session_info.email);
                        pos += session_info.email.length();
                    }
                }
                
                response_json = {
                    {"status", route.response.status},
                    {"headers", {
                        {"Content-Type", route.response.content_type},
                        {"Content-Length", std::to_string(processed_body.size())}
                    }},
                    {"body", processed_body}
                };
                break;
            }
        }
    }

    if (!route_found) {
        // 404 Not Found
        std::string not_found_body = R"(
<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; 
               padding: 20px; text-align: center; }
        .error { background: #fef; color: #c0c; padding: 30px; border-radius: 10px; }
    </style>
</head>
<body>
    <div class="error">
        <h1>404 Not Found</h1>
        <p>The requested page was not found.</p>
        <p><a href="/">Go to Homepage</a></p>
    </div>
</body>
</html>
)";
        response_json = {
            {"status", 404},
            {"headers", {
                {"Content-Type", "text/html"},
                {"Content-Length", std::to_string(not_found_body.size())}
            }},
            {"body", not_found_body}
        };
    }

    // Build and send response
    std::map<std::string, std::string> response_headers;
    for (auto& header : response_json["headers"].items()) {
        response_headers[header.key()] = header.value().get<std::string>();
    }
    
    sendHttpResponse(client_socket, use_ssl, ssl,
                    response_json["status"].get<int>(),
                    response_headers,
                    response_json["body"].get<std::string>());
    
    logger->log(LogLevel::DEBUG, "Response sent: " + std::to_string(response_json["status"].get<int>()) + 
                " for " + path);
    
    // Cleanup
    if (use_ssl && ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(client_socket);
}