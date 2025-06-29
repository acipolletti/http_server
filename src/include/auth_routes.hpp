// src/auth_routes.hpp
#ifndef AUTH_ROUTES_HPP
#define AUTH_ROUTES_HPP

#include <string>
#include <map>
#include <vector>

// Forward declarations
namespace Auth {
    class AuthManager;
}
class Logger;

namespace AuthRoutes {

// HTTP response structure
struct HttpResponse {
    int status_code;
    std::map<std::string, std::string> headers;
    std::string body;
};

// Route handler for authentication endpoints
class RouteHandler {
public:
    RouteHandler(Auth::AuthManager* auth_manager, Logger* logger,std::string home_folder);
    
    // Main request handler
    HttpResponse handleRequest(const std::string& method, const std::string& path,
                             const std::string& headers, const std::string& body);

private:
    Auth::AuthManager* auth_manager_;
    Logger* logger_;
    std::string home_folder_;
    
    // API endpoints
    HttpResponse handleRegister(const std::string& body);
    HttpResponse handleVerify(const std::string& body);
    HttpResponse handleLogin(const std::string& body,const std::string&);
    HttpResponse handleLogout(const std::string& session_token);
    HttpResponse handleStatus(const std::string& session_token);
    
    // HTML pages
    HttpResponse serveRegisterPage();
    HttpResponse serveLoginPage();
    HttpResponse serveVerifyPage();
    
    // New method for serving pages with authentication
    HttpResponse servePage(const std::string& session_token, const std::string& method, const std::string& path);
};

// Utility functions
std::map<std::string, std::string> parseFormData(const std::string& data);
std::string getCookieValue(const std::string& headers, const std::string& cookie_name);

} // namespace AuthRoutes

#endif // AUTH_ROUTES_HPP