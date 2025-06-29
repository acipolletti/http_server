#include <string>
#include <sstream>
#include <iostream>
#include <fstream>

#include <map>
#include <cstring>  // Added for potential string operations
#include <iomanip>  // Added for std::setw and std::hex
#include <cctype>   // Added for isalnum
#include "auth_routes.hpp"
#include "auth.hpp"
#include "logger.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace AuthRoutes {

// Parse URL-encoded form data
std::map<std::string, std::string> parseFormData(const std::string& data) {
    std::map<std::string, std::string> result;
    std::istringstream stream(data);
    std::string pair;
    
    while (std::getline(stream, pair, '&')) {
        size_t eq_pos = pair.find('=');
        if (eq_pos != std::string::npos) {
            std::string key = pair.substr(0, eq_pos);
            std::string value = pair.substr(eq_pos + 1);
            
            // URL decode (simplified - only handles basic cases)
            size_t pos = 0;
            while ((pos = value.find('+', pos)) != std::string::npos) {
                value[pos] = ' ';
            }
            
            result[key] = value;
        }
    }
    
    return result;
}

// Parse cookies from header
std::string getCookieValue(const std::string& headers, const std::string& cookie_name) {
    size_t cookie_pos = headers.find("Cookie:");
    if (cookie_pos == std::string::npos) return "";
    
    size_t cookie_start = headers.find('\n', cookie_pos);
    if (cookie_start == std::string::npos) return "";
    
    size_t cookie_end = headers.find("\r\n", cookie_start);
    std::string cookie_line = headers.substr(cookie_start, cookie_end - cookie_start);
    
    size_t name_pos = cookie_line.find(cookie_name + "=");
    if (name_pos == std::string::npos) return "";
    
    size_t value_start = name_pos + cookie_name.length() + 1;
    size_t value_end = cookie_line.find(';', value_start);
    
    if (value_end == std::string::npos) {
        return cookie_line.substr(value_start);
    }
    
    return cookie_line.substr(value_start, value_end - value_start);
}

RouteHandler::RouteHandler(Auth::AuthManager* auth_manager, Logger* logger, std::string home_folder)
    : auth_manager_(auth_manager), logger_(logger), home_folder_(home_folder) {
    logger_->log(LogLevel::DEBUG, ">>> Entering RouteHandler constructor");
    logger_->log(LogLevel::DEBUG, "<<< Exiting RouteHandler constructor");
}

// Add this helper function to parse query parameters from a path
std::map<std::string, std::string> parseQueryParams(const std::string& path) {
    std::map<std::string, std::string> params;
    
    size_t query_start = path.find('?');
    if (query_start == std::string::npos) {
        return params;
    }
    
    std::string query = path.substr(query_start + 1);
    std::istringstream stream(query);
    std::string pair;
    
    while (std::getline(stream, pair, '&')) {
        size_t eq_pos = pair.find('=');
        if (eq_pos != std::string::npos) {
            std::string key = pair.substr(0, eq_pos);
            std::string value = pair.substr(eq_pos + 1);
            
            // URL decode the value
            size_t pos = 0;
            while ((pos = value.find('+', pos)) != std::string::npos) {
                value[pos] = ' ';
            }
            
            // Decode percent-encoded characters
            pos = 0;
            while ((pos = value.find('%', pos)) != std::string::npos) {
                if (pos + 2 < value.length()) {
                    std::string hex = value.substr(pos + 1, 2);
                    char ch = static_cast<char>(std::stoi(hex, nullptr, 16));
                    value.replace(pos, 3, 1, ch);
                }
                pos++;
            }
            
            params[key] = value;
        }
    }
    // Range-based for loop with structured bindings (C++17)
    for (const auto& [key, value] : params) {
        std::cout << key << ": " << value << '\n';
    }
    return params;
}

// Modified handleRequest method to pass the full path with query params
HttpResponse RouteHandler::handleRequest(const std::string& method, const std::string& path,
                                       const std::string& headers, const std::string& body) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleRequest() - method: " + method + ", path: " + path);
    
    // Extract session cookie
    std::string session_token = getCookieValue(headers, "session");
    
    // Extract base path without query parameters for routing
    std::string base_path = path;
    size_t query_pos = path.find('?');
    if (query_pos != std::string::npos) {
        base_path = path.substr(0, query_pos);
    }
    
    // Route to appropriate handler
    HttpResponse response;
    
    if (base_path == "/auth/register" && method == "POST") {
        response = handleRegister(body);
    } else if (base_path == "/auth/verify" && method == "POST") {
        response = handleVerify(body);
    } else if (base_path == "/auth/login" && method == "POST") {
        // Pass the full path with query parameters to handleLogin
        response = handleLogin(body, path);
    } else if (base_path == "/auth/logout" && method == "POST") {
        response = handleLogout(session_token);
    } else if (base_path == "/auth/status" && method == "GET") {
        response = handleStatus(session_token);
    } else if (base_path == "/auth/register" && method == "GET") {
        response = serveRegisterPage();
    } else if (base_path == "/auth/login" && method == "GET") {
        response = serveLoginPage();
    } else if (base_path == "/auth/verify" && method == "GET") {
        response = serveVerifyPage();
    } else {
        // For all other routes, use servePage with authentication check
        response = servePage(session_token, method, path);
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleRequest() - status: " + std::to_string(response.status_code));
    return response;
}

// Fixed handleLogin method for auth_routes.cpp
HttpResponse RouteHandler::handleLogin(const std::string& body, const std::string& full_path) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleLogin() " + full_path + "\n" + body);
    
    try {
        json request = json::parse(body);
        
        std::string username = request.value("username", "");
        std::string password = request.value("password", "");
        
        logger_->log(LogLevel::DEBUG, "Login attempt for user: " + username);
        
        auto result = auth_manager_->loginUser(username, password);
        
        json response;
        response["success"] = result.success;
        
        if (result.success) {
            // Use the session token from the result structure
            std::string session_token = result.session_token;
            
            // Create session cookie
            std::string cookie = auth_manager_->createSessionCookie(session_token);
            
            // Extract redirect parameter from the full path
            auto query_params = parseQueryParams(full_path);
            std::string redirect_path = "/"; // default redirect
            
            if (query_params.find("redirect") != query_params.end()) {
                redirect_path = query_params["redirect"];
                logger_->log(LogLevel::DEBUG, "Found redirect parameter: " + redirect_path);
            }
            
            // Add redirect path to response
            response["redirect"] = redirect_path;
            response["message"] = result.message;
            
            logger_->log(LogLevel::DEBUG, "Setting session cookie for token: " + session_token);
            logger_->log(LogLevel::DEBUG, "<<< Exiting handleLogin() - success");
            
            return {
                200,
                {
                    {"Content-Type", "application/json"},
                    {"Set-Cookie", cookie}
                },
                response.dump()
            };
            
        } else {
            response["message"] = result.message;
            logger_->log(LogLevel::DEBUG, "<<< Exiting handleLogin() - failed");
            return {
                401,
                {{"Content-Type", "application/json"}},
                response.dump()
            };
        }
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "handleLogin() exception: " + std::string(e.what()));
        json error;
        error["success"] = false;
        error["message"] = "Invalid request format";
        
        logger_->log(LogLevel::DEBUG, "<<< Exiting handleLogin() - exception");
        return {400, {{"Content-Type", "application/json"}}, error.dump()};
    }
}

// Add this URL encoding utility function in auth_routes.cpp (before servePage method)
std::string urlEncode(const std::string& value) {
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

    return escaped.str();
}

// Updated servePage method implementation
HttpResponse RouteHandler::servePage(const std::string& session_token, const std::string& method, const std::string& path) {
    logger_->log(LogLevel::DEBUG, ">>> Entering servePage() - method: " + method + ", path: " + path);
    
    // Verify session token
    if (session_token.empty()) {
        logger_->log(LogLevel::DEBUG, "No session token provided, redirecting to login");
        logger_->log(LogLevel::DEBUG, "<<< Exiting servePage() - no token");
        
        // Encode the original requested path as a query parameter
        std::string redirect_url = "/auth/login?redirect=" + urlEncode(path);
        
        return {
            302,
            {
                {"Location", redirect_url},
                {"Content-Type", "text/html"}
            },
            "<html><body>Redirecting to <a href=\"" + redirect_url + "\">login</a>...</body></html>"
        };
    }
    
    // Validate the session
    auto session = auth_manager_->validateSession(session_token);
    if (!session.valid) {
        logger_->log(LogLevel::DEBUG, "Invalid session token, redirecting to login");
        logger_->log(LogLevel::DEBUG, "<<< Exiting servePage() - invalid token");
        
        // Encode the original requested path as a query parameter
        std::string redirect_url = "/auth/login?redirect=" + urlEncode(path);
        
        return {
            302,
            {
                {"Location", redirect_url},
                {"Content-Type", "text/html"},
                {"Set-Cookie", auth_manager_->createLogoutCookie()} // Clear invalid session
            },
            "<html><body>Session expired. Redirecting to <a href=\"" + redirect_url + "\">login</a>...</body></html>"
        };
    }
    
    logger_->log(LogLevel::DEBUG, "Valid session for user: " + session.username);
    std::string new_path=path;
    const std::string target = "auth";
    const std::string replacement = "authok";

    // Find the position of the substring
    size_t pos = new_path.find(target);
    if (pos != std::string::npos) {
        // Replace "auth" with "authok"
        new_path.replace(pos, target.length(), replacement);
    }
    
    // Process the request based on path
    // Here you can add custom page handling based on the authenticated user
    // For now, we'll return a simple authenticated page
    
    if (method == "GET") {
        std::string filename = home_folder_ + new_path + ".html";
        std::ifstream file(filename, std::ios::in | std::ios::binary);  // binary mode avoids newline transformations
        if (!file) {
            throw std::ios_base::failure("Failed to open file: " + filename);
        }

        // Read contents into a string using iterators
        std::string html((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        
        logger_->log(LogLevel::DEBUG, "<<< Exiting servePage() - serving home page");
        return {
            200,
            {{"Content-Type", "text/html"}},
            html
        };
    }
    
    // Default: Route not found
    logger_->log(LogLevel::DEBUG, "<<< Exiting servePage() - route not found");
    return {
        404,
        {{"Content-Type", "text/html"}},
        R"(
<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
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
        <h1>404 Not Found</h1>
        <p>The requested page does not exist.</p>
        <p><a href="/">Go to Home</a></p>
    </div>
</body>
</html>
)"
    };
}

HttpResponse RouteHandler::handleRegister(const std::string& body) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleRegister()");
    
    try {
        json request = json::parse(body);
        
        std::string username = request.value("username", "");
        std::string password = request.value("password", "");
        std::string email = request.value("email", "");
        
        logger_->log(LogLevel::DEBUG, "Registering user: " + username + ", email: " + email);
        
        auto result = auth_manager_->registerUser(username, password, email);
        
        json response;
        response["success"] = result.success;
        response["message"] = result.message;
        
        if (result.success) {
            response["user_id"] = result.user_id;
        }
        
        logger_->log(LogLevel::DEBUG, "<<< Exiting handleRegister() - success: " + std::to_string(result.success));
        return {
            result.success ? 200 : 400,
            {{"Content-Type", "application/json"}},
            response.dump()
        };
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "handleRegister() exception: " + std::string(e.what()));
        json error;
        error["success"] = false;
        error["message"] = "Invalid request format";
        
        logger_->log(LogLevel::DEBUG, "<<< Exiting handleRegister() - exception");
        return {400, {{"Content-Type", "application/json"}}, error.dump()};
    }
}

HttpResponse RouteHandler::handleVerify(const std::string& body) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleVerify()");
    
    try {
        json request = json::parse(body);
        
        std::string username = request.value("username", "");
        std::string code = request.value("code", "");
        
        logger_->log(LogLevel::DEBUG, "Verifying user: " + username);
        
        auto result = auth_manager_->verifyUser(username, code);
        
        json response;
        response["success"] = result.success;
        response["message"] = result.message;
        
        logger_->log(LogLevel::DEBUG, "<<< Exiting handleVerify() - success: " + std::to_string(result.success));
        return {
            result.success ? 200 : 400,
            {{"Content-Type", "application/json"}},
            response.dump()
        };
    } catch (const std::exception& e) {
        logger_->log(LogLevel::ERROR, "handleVerify() exception: " + std::string(e.what()));
        json error;
        error["success"] = false;
        error["message"] = "Invalid request format";
        
        logger_->log(LogLevel::DEBUG, "<<< Exiting handleVerify() - exception");
        return {400, {{"Content-Type", "application/json"}}, error.dump()};
    }
}


HttpResponse RouteHandler::handleLogout(const std::string& session_token) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleLogout()");
    
    bool success = false;
    if (!session_token.empty()) {
        success = auth_manager_->logoutUser(session_token);
    }
    
    json response;
    response["success"] = success;
    response["message"] = success ? "Logged out successfully" : "No active session";
    
    // Clear session cookie
    std::string cookie = auth_manager_->createLogoutCookie();
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleLogout() - success: " + std::to_string(success));
    return {
        200,
        {
            {"Content-Type", "application/json"},
            {"Set-Cookie", cookie}
        },
        response.dump()
    };
}

HttpResponse RouteHandler::handleStatus(const std::string& session_token) {
    logger_->log(LogLevel::DEBUG, ">>> Entering handleStatus()");
    
    json response;
    
    if (session_token.empty()) {
        response["authenticated"] = false;
        response["message"] = "Not authenticated";
    } else {
        auto session = auth_manager_->validateSession(session_token);
        response["authenticated"] = session.valid;
        
        if (session.valid) {
            response["user_id"] = session.user_id;
            response["username"] = session.username;
            response["email"] = session.email;
        } else {
            response["message"] = "Invalid or expired session";
        }
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting handleStatus() - authenticated: " + 
                std::to_string(response["authenticated"].get<bool>()));
    return {
        200,
        {{"Content-Type", "application/json"}},
        response.dump()
    };
}

HttpResponse RouteHandler::serveRegisterPage() {
    logger_->log(LogLevel::DEBUG, ">>> Entering serveRegisterPage()");
    
    std::string html = R"html(
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="email"], input[type="password"] { 
            width: 100%; 
            padding: 8px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            box-sizing: border-box;
        }
        button { 
            width: 100%; 
            padding: 10px; 
            background: #007bff; 
            color: white; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            font-size: 16px;
        }
        button:hover { background: #0056b3; }
        .error { color: red; margin-top: 10px; }
        .success { color: green; margin-top: 10px; }
        .checkbox-group { 
            display: flex; 
            align-items: center; 
            margin-top: 5px; 
            margin-bottom: 15px;
        }
        .checkbox-group input[type="checkbox"] { 
            margin-right: 8px; 
            width: auto; 
        }
        .checkbox-group label { 
            margin-bottom: 0; 
            font-weight: normal;
            cursor: pointer;
            user-select: none;
        }
        .password-requirements {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        .password-wrapper {
            position: relative;
        }
        .password-strength {
            margin-top: 5px;
            height: 4px;
            background: #e0e0e0;
            border-radius: 2px;
            overflow: hidden;
        }
        .password-strength-bar {
            height: 100%;
            width: 0%;
            transition: width 0.3s, background-color 0.3s;
        }
        .strength-weak { background-color: #dc3545; }
        .strength-medium { background-color: #ffc107; }
        .strength-strong { background-color: #28a745; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h2>Create Account</h2>
    <form id="registerForm">
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required minlength="3" maxlength="20" 
                   placeholder="Choose a username" autocomplete="username">
            <div class="password-requirements">3-20 characters, letters, numbers, and underscores only</div>
        </div>
        <div class="form-group">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required 
                   placeholder="your@email.com" autocomplete="email">
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <div class="password-wrapper">
                <input type="password" id="password" name="password" required minlength="8" 
                       placeholder="Choose a strong password" autocomplete="new-password">
                <div class="password-strength">
                    <div id="strengthBar" class="password-strength-bar"></div>
                </div>
                <div class="password-requirements">Minimum 8 characters</div>
            </div>
        </div>
        <div class="checkbox-group">
            <input type="checkbox" id="showPassword" onchange="togglePassword()">
            <label for="showPassword">Show password</label>
        </div>
        <button type="submit">Register</button>
    </form>
    <div id="message"></div>
    <p style="text-align: center; margin-top: 20px;">
        Already have an account? <a href="/auth/login">Login</a>
    </p>
    
    <script>
    // Toggle password visibility
    function togglePassword() {
        const passwordInput = document.getElementById('password');
        const checkbox = document.getElementById('showPassword');
        passwordInput.type = checkbox.checked ? 'text' : 'password';
    }
    
    // Password strength checker
    function checkPasswordStrength(password) {
        let strength = 0;
        
        // Length check
        if (password.length >= 8) strength += 1;
        if (password.length >= 12) strength += 1;
        
        // Character variety checks
        if (/[a-z]/.test(password)) strength += 1;
        if (/[A-Z]/.test(password)) strength += 1;
        if (/[0-9]/.test(password)) strength += 1;
        if (/[^A-Za-z0-9]/.test(password)) strength += 1;
        
        return strength;
    }
    
    // Update password strength indicator
    document.getElementById('password').addEventListener('input', function(e) {
        const password = e.target.value;
        const strengthBar = document.getElementById('strengthBar');
        const strength = checkPasswordStrength(password);
        
        // Update bar width
        let width = 0;
        let strengthClass = '';
        
        if (strength <= 2) {
            width = 33;
            strengthClass = 'strength-weak';
        } else if (strength <= 4) {
            width = 66;
            strengthClass = 'strength-medium';
        } else {
            width = 100;
            strengthClass = 'strength-strong';
        }
        
        strengthBar.style.width = width + '%';
        strengthBar.className = 'password-strength-bar ' + strengthClass;
    });
    
    // Form submission
    document.getElementById('registerForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const messageDiv = document.getElementById('message');
        const submitButton = e.target.querySelector('button[type="submit"]');
        
        // Disable submit button to prevent double submission
        submitButton.disabled = true;
        submitButton.textContent = 'Creating account...';
        
        try {
            const response = await fetch('/auth/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('username').value.trim(),
                    email: document.getElementById('email').value.trim(),
                    password: document.getElementById('password').value
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                messageDiv.className = 'success';
                messageDiv.textContent = data.message + ' Redirecting to verification...';
                
                // Store username for verification page
                sessionStorage.setItem('pendingUsername', document.getElementById('username').value.trim());
                
                setTimeout(() => window.location.href = '/auth/verify', 2000);
            } else {
                messageDiv.className = 'error';
                messageDiv.textContent = data.message;
                submitButton.disabled = false;
                submitButton.textContent = 'Register';
            }
        } catch (error) {
            messageDiv.className = 'error';
            messageDiv.textContent = 'Registration failed. Please try again.';
            submitButton.disabled = false;
            submitButton.textContent = 'Register';
        }
    });
    
    // Auto-focus first field
    document.getElementById('username').focus();
    </script>
</body>
</html>
)html";
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting serveRegisterPage()");
    return {200, {{"Content-Type", "text/html"}}, html};
}
HttpResponse RouteHandler::serveLoginPage() {
    logger_->log(LogLevel::DEBUG, ">>> Entering serveLoginPage()");
    
    std::string html = R"html(
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { 
            width: 100%; 
            padding: 8px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            box-sizing: border-box;
        }
        button { 
            width: 100%; 
            padding: 10px; 
            background: #007bff; 
            color: white; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer;
            font-size: 16px;
        }
        button:hover { background: #0056b3; }
        button:disabled { 
            background: #6c757d; 
            cursor: not-allowed; 
        }
        .error { color: red; margin-top: 10px; }
        .success { color: green; margin-top: 10px; }
        .checkbox-group { 
            display: flex; 
            align-items: center; 
            margin-top: 5px; 
            margin-bottom: 15px;
        }
        .checkbox-group input[type="checkbox"] { 
            margin-right: 8px; 
            width: auto; 
        }
        .checkbox-group label { 
            margin-bottom: 0; 
            font-weight: normal;
            cursor: pointer;
            user-select: none;
        }
        .forgot-password {
            text-align: right;
            margin-top: 5px;
            font-size: 14px;
        }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .divider {
            text-align: center;
            margin: 20px 0;
            color: #666;
        }
        .info-box {
            background: #e7f3ff;
            border: 1px solid #b3d9ff;
            border-radius: 4px;
            padding: 10px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }
        .info-box.show { display: block; }
    </style>
</head>
<body>
    <h2>Login</h2>
    
    <div id="infoBox" class="info-box"></div>
    
    <form id="loginForm">
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required 
                   placeholder="Enter your username" autocomplete="username">
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required 
                   placeholder="Enter your password" autocomplete="current-password">
            <div class="forgot-password">
                <a href="#" onclick="alert('Password reset feature coming soon!'); return false;">Forgot password?</a>
            </div>
        </div>
        <div class="checkbox-group">
            <input type="checkbox" id="showPassword" onchange="togglePassword()">
            <label for="showPassword">Show password</label>
        </div>
        <button type="submit" id="submitButton">Login</button>
    </form>
    <div id="message"></div>
    <div class="divider">— OR —</div>
    <p style="text-align: center;">
        Don't have an account? <a href="/auth/register">Create one</a>
    </p>
    
    <script>
    // Toggle password visibility
    function togglePassword() {
        const passwordInput = document.getElementById('password');
        const checkbox = document.getElementById('showPassword');
        passwordInput.type = checkbox.checked ? 'text' : 'password';
    }
    
    // Get current URL with query parameters
    function getCurrentUrl() {
        const path = window.location.pathname;
        const query = window.location.search;
        return path + query;
    }
    
    // Check if coming from registration or other events
    window.addEventListener('DOMContentLoaded', () => {
        const urlParams = new URLSearchParams(window.location.search);
        const infoBox = document.getElementById('infoBox');
        
        if (urlParams.get('registered') === 'true') {
            infoBox.textContent = 'Registration successful! Please login with your credentials.';
            infoBox.classList.add('show');
            infoBox.style.background = '#d4edda';
            infoBox.style.borderColor = '#c3e6cb';
            infoBox.style.color = '#155724';
        } else if (urlParams.get('session') === 'expired') {
            infoBox.textContent = 'Your session has expired. Please login again.';
            infoBox.classList.add('show');
        } else if (urlParams.get('logout') === 'true') {
            infoBox.textContent = 'You have been successfully logged out.';
            infoBox.classList.add('show');
            infoBox.style.background = '#d4edda';
            infoBox.style.borderColor = '#c3e6cb';
            infoBox.style.color = '#155724';
        }
        
        // Auto-focus username field
        document.getElementById('username').focus();
    });
    
    // Form submission
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const messageDiv = document.getElementById('message');
        const submitButton = document.getElementById('submitButton');
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        
        // Clear previous messages
        messageDiv.textContent = '';
        messageDiv.className = '';
        
        // Validate input
        if (!username || !password) {
            messageDiv.className = 'error';
            messageDiv.textContent = 'Please enter both username and password.';
            return;
        }
        
        // Disable submit button
        submitButton.disabled = true;
        submitButton.textContent = 'Logging in...';
        
        try {
            // Use the current URL to preserve query parameters
            const loginUrl = getCurrentUrl();
            
            console.log('Sending login request to:', loginUrl);
            
            const response = await fetch(loginUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'same-origin', // Important for cookie handling
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            });
            
            console.log('Response status:', response.status);
            console.log('Response headers:', response.headers);
            
            // Check if response is JSON
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                throw new Error('Server returned non-JSON response');
            }
            
            const data = await response.json();
            console.log('Response data:', data);
            
            if (data.success) {
                messageDiv.className = 'success';
                messageDiv.textContent = 'Login successful! Redirecting...';
                
                // Get redirect URL from response or query params
                const urlParams = new URLSearchParams(window.location.search);
                const redirect = data.redirect || urlParams.get('redirect') || '/dashboard';
                
                console.log('Redirecting to:', redirect);
                
                // Redirect after a short delay
                setTimeout(() => {
                    window.location.href = redirect;
                }, 1000);
            } else {
                messageDiv.className = 'error';
                messageDiv.textContent = data.message || 'Login failed. Please check your credentials.';
                submitButton.disabled = false;
                submitButton.textContent = 'Login';
                
                // Clear password field on error
                document.getElementById('password').value = '';
                document.getElementById('password').focus();
            }
        } catch (error) {
            console.error('Login error:', error);
            messageDiv.className = 'error';
            messageDiv.textContent = 'Login failed. Please check your connection and try again.';
            submitButton.disabled = false;
            submitButton.textContent = 'Login';
            
            // Clear password field on error
            document.getElementById('password').value = '';
        }
    });
    
    // Handle Enter key in username field
    document.getElementById('username').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const passwordField = document.getElementById('password');
            if (passwordField.value) {
                // If password is already filled, submit the form
                document.getElementById('loginForm').dispatchEvent(new Event('submit'));
            } else {
                // Otherwise, focus on password field
                passwordField.focus();
            }
        }
    });
    
    // Add visual feedback for caps lock
    document.getElementById('password').addEventListener('keyup', (e) => {
        const capsLockOn = e.getModifierState && e.getModifierState('CapsLock');
        const messageDiv = document.getElementById('message');
        
        if (capsLockOn && !messageDiv.textContent) {
            messageDiv.className = 'error';
            messageDiv.textContent = 'Caps Lock is on';
        } else if (!capsLockOn && messageDiv.textContent === 'Caps Lock is on') {
            messageDiv.textContent = '';
            messageDiv.className = '';
        }
    });
    </script>
</body>
</html>
)html";
    
    HttpResponse response;
    response.status_code = 200;
    response.headers["Content-Type"] = "text/html; charset=UTF-8";
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
    response.headers["Pragma"] = "no-cache";
    response.headers["Expires"] = "0";
    response.body = html;
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting serveLoginPage()");
    return response;
}

HttpResponse RouteHandler::serveVerifyPage() {
    logger_->log(LogLevel::DEBUG, ">>> Entering serveVerifyPage()");
    
    std::string html = R"html(
<!DOCTYPE html>
<html>
<head>
    <title>Verify Email</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"] { 
            width: 100%; 
            padding: 8px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            box-sizing: border-box;
        }
        button { 
            width: 100%; 
            padding: 10px; 
            background: #007bff; 
            color: white; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer;
            font-size: 16px;
        }
        button:hover { background: #0056b3; }
        .error { color: red; margin-top: 10px; }
        .success { color: green; margin-top: 10px; }
        .info { 
            background: #e3f2fd; 
            padding: 15px; 
            border-radius: 4px; 
            margin-bottom: 20px;
            border-left: 4px solid #2196f3;
        }
        .code-input {
            text-align: center;
            font-size: 24px;
            letter-spacing: 8px;
            font-family: monospace;
        }
        .resend-link {
            text-align: center;
            margin-top: 15px;
            font-size: 14px;
        }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .email-icon {
            text-align: center;
            font-size: 48px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="email-icon">📧</div>
    <h2>Verify Your Email</h2>
    <div class="info">
        We've sent a 6-digit verification code to your email address. 
        Please enter it below to complete your registration.
    </div>
    <form id="verifyForm">
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required 
                   placeholder="Enter your username">
        </div>
        <div class="form-group">
            <label for="code">Verification Code:</label>
            <input type="text" 
                   id="code" 
                   name="code" 
                   required 
                   pattern="[0-9]{6}" 
                   maxlength="6" 
                   placeholder="000000"
                   class="code-input"
                   autocomplete="one-time-code">
        </div>
        <button type="submit">Verify Email</button>
    </form>
    <div id="message"></div>
    <div class="resend-link">
        Didn't receive the code? 
        <a href="#" onclick="resendCode(); return false;">Resend verification email</a>
    </div>
    <p style="text-align: center; margin-top: 20px;">
        <a href="/auth/login">Back to login</a>
    </p>
    
    <script>
    // Auto-fill username if stored from registration
    window.addEventListener('DOMContentLoaded', () => {
        const storedUsername = sessionStorage.getItem('pendingUsername');
        if (storedUsername) {
            document.getElementById('username').value = storedUsername;
            document.getElementById('code').focus();
        } else {
            document.getElementById('username').focus();
        }
    });
    
    // Auto-format code input
    document.getElementById('code').addEventListener('input', function(e) {
        // Remove non-digits
        e.target.value = e.target.value.replace(/\D/g, '');
        
        // Auto-submit when 6 digits entered
        if (e.target.value.length === 6) {
            document.getElementById('verifyForm').dispatchEvent(new Event('submit'));
        }
    });
    
    // Paste handler for code
    document.getElementById('code').addEventListener('paste', function(e) {
        e.preventDefault();
        const paste = (e.clipboardData || window.clipboardData).getData('text');
        const digits = paste.replace(/\D/g, '').slice(0, 6);
        e.target.value = digits;
        
        if (digits.length === 6) {
            setTimeout(() => {
                document.getElementById('verifyForm').dispatchEvent(new Event('submit'));
            }, 100);
        }
    });
    
    // Form submission
    document.getElementById('verifyForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const messageDiv = document.getElementById('message');
        const submitButton = e.target.querySelector('button[type="submit"]');
        
        // Validate code length
        const code = document.getElementById('code').value;
        if (code.length !== 6) {
            messageDiv.className = 'error';
            messageDiv.textContent = 'Please enter a 6-digit code';
            return;
        }
        
        // Disable submit button
        submitButton.disabled = true;
        submitButton.textContent = 'Verifying...';
        
        try {
            const response = await fetch('/auth/verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('username').value.trim(),
                    code: code
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                messageDiv.className = 'success';
                messageDiv.textContent = data.message + ' Redirecting to login...';
                
                // Clear stored username
                sessionStorage.removeItem('pendingUsername');
                
                setTimeout(() => window.location.href = '/auth/login?registered=true', 2000);
            } else {
                messageDiv.className = 'error';
                messageDiv.textContent = data.message;
                submitButton.disabled = false;
                submitButton.textContent = 'Verify Email';
                
                // Clear code on error
                document.getElementById('code').value = '';
                document.getElementById('code').focus();
            }
        } catch (error) {
            messageDiv.className = 'error';
            messageDiv.textContent = 'Verification failed. Please try again.';
            submitButton.disabled = false;
            submitButton.textContent = 'Verify Email';
        }
    });
    
    // Resend code function
    async function resendCode() {
        const username = document.getElementById('username').value.trim();
        if (!username) {
            alert('Please enter your username first');
            document.getElementById('username').focus();
            return;
        }
        
        const messageDiv = document.getElementById('message');
        messageDiv.className = 'info';
        messageDiv.textContent = 'Sending new verification code...';
        
        // Note: This would require a new API endpoint to resend verification
        setTimeout(() => {
            messageDiv.className = 'success';
            messageDiv.textContent = 'New verification code sent! Check your email.';
        }, 1000);
    }
    </script>
</body>
</html>
)html";
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting serveVerifyPage()");
    return {200, {{"Content-Type", "text/html"}}, html};
}

} // namespace AuthRoutes