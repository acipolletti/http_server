// src/auth.hpp
#ifndef AUTH_HPP
#define AUTH_HPP
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

// Forward declarations
class Logger;
struct sqlite3;

namespace Auth {

// Configuration for authentication system
struct AuthConfig {
    std::string database_path = "users.db";
    int session_lifetime = 86400; // 24 hours in seconds
    bool extend_session_on_activity = true;
    
    // User folder settings
    bool create_user_folders = true;
    std::string user_storage_path; // Base path for user storage folders
    
    // SMTP settings for email verification
    std::string smtp_server;
    std::string smtp_username;
    std::string smtp_password;
    std::string smtp_from = "noreply@example.com";
    int smtp_port = 587;
};

// Result of authentication operations
struct AuthResult {
    bool success;
    std::string message;
    int64_t user_id = 0;
    std::string session_token;  // Added this field for login operations
};

// Session information
struct SessionInfo {
    bool valid;
    int64_t user_id;
    std::string username;
    std::string email;
};

// Email upload context for CURL
struct EmailUploadStatus {
    std::string payload;
    size_t bytes_read;
};

// Main authentication manager class
class AuthManager {
public:
    AuthManager(const AuthConfig& config, Logger* logger);
    ~AuthManager();

    // User registration and verification
    AuthResult registerUser(const std::string& username, const std::string& password, 
                          const std::string& email);
    AuthResult verifyUser(const std::string& username, const std::string& code);
    
    // User authentication
    AuthResult loginUser(const std::string& username, const std::string& password);
    bool logoutUser(const std::string& token);
    
    // Session management
    SessionInfo validateSession(const std::string& token);
    std::string extractSessionFromCookies(const std::string& cookie_header);
    std::string createSessionCookie(const std::string& token);
    std::string createLogoutCookie();

private:
    AuthConfig config_;
    Logger* logger_;
    sqlite3* db_;
    
    // Thread safety
    mutable std::mutex db_mutex_;
    
    // Cleanup thread
    std::thread cleanup_thread_;
    std::atomic<bool> cleanup_running_{true};
    std::mutex cleanup_mutex_;
    std::condition_variable cleanup_cv_;
    
    // Database operations
    void initDatabase();
    void cleanupExpiredSessions();
    void cleanupExpiredVerifications();
    void extendSession(const std::string& token);
    
    // Email operations
    bool sendVerificationEmail(const std::string& email, const std::string& username,
                             const std::string& code);
    
    // Cleanup thread
    void startCleanupThread();
};

// Utility functions
std::string hashPassword(const std::string& password, const std::string& salt);
std::string generateSalt(size_t length = 32);
std::string generateSessionToken();
std::string generateVerificationCode();
bool isValidEmail(const std::string& email);
bool isValidUsername(const std::string& username);

} // namespace Auth

#endif // AUTH_HPP