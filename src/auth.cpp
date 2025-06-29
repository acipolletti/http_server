// src/auth.cpp
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <mutex>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <regex>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <ctime>
#include <cstring>  // Added for strlen and memcpy
#include <memory>
#include <vector>
#include <curl/curl.h>
#include "auth.hpp"
#include "logger.hpp"
namespace fs = std::filesystem;

extern int SendGmail(std::string gmail_address,std::string app_password,std::string send_to,std::string vcode) ;

namespace Auth {

// Helper function for SMTP response
static size_t smtp_payload_source(void *ptr, size_t size, size_t nmemb, void *userp) {
    auto *upload_ctx = static_cast<EmailUploadStatus*>(userp);
    const char *data;

    if ((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
        return 0;
    }

    data = &upload_ctx->payload[upload_ctx->bytes_read];

    if (data) {
        size_t len = strlen(data);
        if (len > size * nmemb) len = size * nmemb;
        memcpy(ptr, data, len);
        upload_ctx->bytes_read += len;
        return len;
    }

    return 0;
}

// SHA256 hashing with salt
std::string hashPassword(const std::string& password, const std::string& salt) {
    std::string salted = password + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(salted.c_str()), salted.length(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Generate random salt
std::string generateSalt(size_t length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string salt;
    salt.reserve(length);
    
    unsigned char random_bytes[length];
    RAND_bytes(random_bytes, length);
    
    for (size_t i = 0; i < length; i++) {
        salt += charset[random_bytes[i] % (sizeof(charset) - 1)];
    }
    
    return salt;
}

// Generate random session token
std::string generateSessionToken() {
    unsigned char buffer[32];
    RAND_bytes(buffer, sizeof(buffer));
    
    std::stringstream ss;
    for (size_t i = 0; i < sizeof(buffer); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
    }
    return ss.str();
}

// Generate 6-digit verification code
std::string generateVerificationCode() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100000, 999999);
    return std::to_string(dis(gen));
}

// Email validation
bool isValidEmail(const std::string& email) {
    const std::regex pattern(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
    return std::regex_match(email, pattern);
}

// Username validation
bool isValidUsername(const std::string& username) {
    if (username.length() < 3 || username.length() > 20) return false;
    const std::regex pattern("^[a-zA-Z0-9_]+$");
    return std::regex_match(username, pattern);
}

// Implementation of AuthManager
AuthManager::AuthManager(const AuthConfig& config, Logger* logger) 
    : config_(config), logger_(logger), db_(nullptr) {
    logger_->log(LogLevel::DEBUG, ">>> Entering AuthManager constructor");
    initDatabase();
    startCleanupThread();
    logger_->log(LogLevel::DEBUG, "<<< Exiting AuthManager constructor");
}

AuthManager::~AuthManager() {
    logger_->log(LogLevel::DEBUG, ">>> Entering AuthManager destructor");
    cleanup_running_ = false;
    if (cleanup_thread_.joinable()) {
        cleanup_cv_.notify_all();
        cleanup_thread_.join();
    }
    if (db_) {
        sqlite3_close(db_);
    }
    logger_->log(LogLevel::DEBUG, "<<< Exiting AuthManager destructor");
}

void AuthManager::initDatabase() {
    logger_->log(LogLevel::DEBUG, ">>> Entering initDatabase()");
    
    int rc = sqlite3_open(config_.database_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::ERROR, "Cannot open database: " + std::string(sqlite3_errmsg(db_)));
        throw std::runtime_error("Database initialization failed");
    }

    // Create users table
    const char* create_users_sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_verified BOOLEAN DEFAULT 0,
            verification_code TEXT,
            verification_expires INTEGER,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            updated_at INTEGER DEFAULT (strftime('%s', 'now'))
        );
    )";

    // Create sessions table
    const char* create_sessions_sql = R"(
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    )";

    // Create indices
    const char* create_indices_sql = R"(
        CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    )";

    char* err_msg = nullptr;
    logger_->log(LogLevel::DEBUG, "Creating users table...");
    rc = sqlite3_exec(db_, create_users_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::ERROR, "Failed to create users table: " + std::string(err_msg));
        sqlite3_free(err_msg);
        throw std::runtime_error("Database initialization failed");
    }

    logger_->log(LogLevel::DEBUG, "Creating sessions table...");
    rc = sqlite3_exec(db_, create_sessions_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::ERROR, "Failed to create sessions table: " + std::string(err_msg));
        sqlite3_free(err_msg);
        throw std::runtime_error("Database initialization failed");
    }

    logger_->log(LogLevel::DEBUG, "Creating indices...");
    rc = sqlite3_exec(db_, create_indices_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::ERROR, "Failed to create indices: " + std::string(err_msg));
        sqlite3_free(err_msg);
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting initDatabase()");
}

void AuthManager::startCleanupThread() {
    logger_->log(LogLevel::DEBUG, ">>> Entering startCleanupThread()");
    
    cleanup_thread_ = std::thread([this]() {
        logger_->log(LogLevel::DEBUG, "Cleanup thread started");
        while (cleanup_running_) {
            std::unique_lock<std::mutex> lock(cleanup_mutex_);
            cleanup_cv_.wait_for(lock, std::chrono::minutes(5), [this]() { 
                return !cleanup_running_; 
            });
            
            if (cleanup_running_) {
                cleanupExpiredSessions();
                cleanupExpiredVerifications();
            }
        }
        logger_->log(LogLevel::DEBUG, "Cleanup thread ending");
    });
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting startCleanupThread()");
}

void AuthManager::cleanupExpiredSessions() {
    logger_->log(LogLevel::DEBUG, ">>> Entering cleanupExpiredSessions()");
    
    std::lock_guard<std::mutex> lock(db_mutex_);
    
    const char* sql = "DELETE FROM sessions WHERE expires_at < strftime('%s', 'now')";
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg);
    
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::ERROR, "Failed to cleanup sessions: " + std::string(err_msg));
        sqlite3_free(err_msg);
    } else {
        int changes = sqlite3_changes(db_);
        if (changes > 0) {
            logger_->log(LogLevel::DEBUG, "Cleaned up " + std::to_string(changes) + " expired sessions");
        }
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting cleanupExpiredSessions()");
}

void AuthManager::cleanupExpiredVerifications() {
    logger_->log(LogLevel::DEBUG, ">>> Entering cleanupExpiredVerifications()");
    
    std::lock_guard<std::mutex> lock(db_mutex_);
    
    const char* sql = R"(
        UPDATE users 
        SET verification_code = NULL, verification_expires = NULL 
        WHERE verification_expires < strftime('%s', 'now') 
    )";
    
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg);
    
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::ERROR, "Failed to cleanup verifications: " + std::string(err_msg));
        sqlite3_free(err_msg);
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting cleanupExpiredVerifications()");
}

AuthResult AuthManager::registerUser(const std::string& username, const std::string& password, 
                                   const std::string& email) {
    logger_->log(LogLevel::DEBUG, ">>> Entering registerUser() - username: " + username + ", email: " + email);
    
    // Validate inputs
    if (!isValidUsername(username)) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting registerUser() - invalid username");
        return {false, "Invalid username. Use 3-20 characters, letters, numbers, and underscores only."};
    }
    
    if (!isValidEmail(email)) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting registerUser() - invalid email");
        return {false, "Invalid email address."};
    }
    
    if (password.length() < 8) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting registerUser() - password too short");
        return {false, "Password must be at least 8 characters long."};
    }

    std::lock_guard<std::mutex> lock(db_mutex_);

    // Check if user already exists
    logger_->log(LogLevel::DEBUG, "Checking if user already exists...");
    const char* check_sql = "SELECT id FROM users WHERE username = ? OR email = ?";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, check_sql, -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting registerUser() - database error");
        return {false, "Database error."};
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc == SQLITE_ROW) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting registerUser() - user already exists");
        return {false, "Username or email already exists."};
    }

    // Generate salt and hash password
    logger_->log(LogLevel::DEBUG, "Generating salt and hashing password...");
    std::string salt = generateSalt();
    std::string password_hash = hashPassword(password, salt);
    
    // Generate verification code
    std::string verification_code = generateVerificationCode();
    int64_t verification_expires = std::time(nullptr) + 3600; // 1 hour

    // Insert new user
    logger_->log(LogLevel::DEBUG, "Inserting new user into database...");
    const char* insert_sql = R"(
        INSERT INTO users (username, email, password_hash, salt, verification_code, verification_expires)
        VALUES (?, ?, ?, ?, ?, ?)
    )";
    
    rc = sqlite3_prepare_v2(db_, insert_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting registerUser() - database error");
        return {false, "Database error."};
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, password_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, salt.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, verification_code.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, verification_expires);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting registerUser() - failed to create user");
        return {false, "Failed to create user."};
    }

    // Send verification email
    logger_->log(LogLevel::DEBUG, "Sending verification email...");
    if (!sendVerificationEmail(email, username, verification_code)) {
        logger_->log(LogLevel::WARNING, "Failed to send verification email to " + email);
    }

    logger_->log(LogLevel::INFO, "New user registered: " + username);
    logger_->log(LogLevel::DEBUG, "<<< Exiting registerUser() - success");
    return {true, "Registration successful. Please check your email for verification code.", 
            sqlite3_last_insert_rowid(db_)};
}

AuthResult AuthManager::verifyUser(const std::string& username, const std::string& code) {
    logger_->log(LogLevel::DEBUG, ">>> Entering verifyUser() - username: " + username);
    
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        SELECT id, verification_code, verification_expires 
        FROM users 
        WHERE username = ? AND is_verified = 0
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting verifyUser() - database error");
        return {false, "Database error."};
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        logger_->log(LogLevel::DEBUG, "<<< Exiting verifyUser() - user not found");
        return {false, "User not found or already verified."};
    }
    
    int64_t user_id = sqlite3_column_int64(stmt, 0);
    std::string stored_code = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    int64_t expires_at = sqlite3_column_int64(stmt, 2);
    sqlite3_finalize(stmt);

    // Log timing information for debugging
    int64_t current_time = std::time(nullptr);
    logger_->log(LogLevel::INFO, "Verification timing check:");
    logger_->log(LogLevel::INFO, "  Current time: " + std::to_string(current_time));
    logger_->log(LogLevel::INFO, "  Expires at: " + std::to_string(expires_at));
    logger_->log(LogLevel::INFO, "  Time difference: " + std::to_string(expires_at - current_time) + " seconds");
    
    // Convert to human-readable format for logging
    char current_time_str[100];
    char expires_time_str[100];
    std::strftime(current_time_str, sizeof(current_time_str), "%Y-%m-%d %H:%M:%S %Z", std::localtime(&current_time));
    std::strftime(expires_time_str, sizeof(expires_time_str), "%Y-%m-%d %H:%M:%S %Z", std::localtime(&expires_at));
    logger_->log(LogLevel::INFO, "  Current time (readable): " + std::string(current_time_str));
    logger_->log(LogLevel::INFO, "  Expires at (readable): " + std::string(expires_time_str));

    // Check if code expired
    if (current_time > expires_at) {
        logger_->log(LogLevel::WARNING, "Verification code expired by " + 
                    std::to_string(current_time - expires_at) + " seconds");
        logger_->log(LogLevel::DEBUG, "<<< Exiting verifyUser() - code expired");
        return {false, "Verification code expired."};
    }

    // Check if code matches
    if (code != stored_code) {
        logger_->log(LogLevel::WARNING, "Invalid verification code provided");
        logger_->log(LogLevel::DEBUG, "<<< Exiting verifyUser() - invalid code");
        return {false, "Invalid verification code."};
    }

    // Update user as verified
    logger_->log(LogLevel::DEBUG, "Updating user as verified...");
    const char* update_sql = R"(
        UPDATE users 
        SET is_verified = 1, verification_code = NULL, verification_expires = NULL,
            updated_at = strftime('%s', 'now')
        WHERE id = ?
    )";
    
    rc = sqlite3_prepare_v2(db_, update_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting verifyUser() - database error");
        return {false, "Database error."};
    }
    
    sqlite3_bind_int64(stmt, 1, user_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting verifyUser() - failed to verify");
        return {false, "Failed to verify user."};
    }

    logger_->log(LogLevel::INFO, "User verified successfully: " + username);
    




   
    // Create user folder
    if (config_.create_user_folders && !config_.user_storage_path.empty()) {
        logger_->log(LogLevel::DEBUG, "Creating user folder for user_id: " + std::to_string(user_id));
        try {
            std::string user_folder = config_.user_storage_path + "/user_" + std::to_string(user_id);
            if (!fs::exists(user_folder)) {
                fs::create_directories(user_folder);
                fs::create_directories(user_folder + "/documents");
                fs::create_directories(user_folder + "/images");
                fs::create_directories(user_folder + "/downloads");
                
                // Create welcome file
                std::ofstream welcome(user_folder + "/README.txt");
                if (welcome.is_open()) {
                    welcome << "Welcome to your personal storage!\n\n";
                    welcome << "You can upload, download, and manage your files here.\n";
                    welcome << "Storage limit: 1GB\n";
                    welcome << "Maximum file size: 100MB\n";
                    welcome.close();
                }
                logger_->log(LogLevel::INFO, "Created user folder: " + user_folder);
            }
        } catch (const std::exception& e) {
            logger_->log(LogLevel::ERROR, "Failed to create user folder: " + std::string(e.what()));
        }
    }
    
    logger_->log(LogLevel::INFO, "New user created folder: " + username);
    logger_->log(LogLevel::DEBUG, "<<< Exiting verifyUser() - success");
   return {true, "Email verified successfully. You can now login.", user_id};


}

// Updated loginUser method for auth.cpp
AuthResult AuthManager::loginUser(const std::string& username, const std::string& password) {
    logger_->log(LogLevel::DEBUG, ">>> Entering loginUser() - username: " + username);
    
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        SELECT id, password_hash, salt, is_verified 
        FROM users 
        WHERE username = ?
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting loginUser() - database error");
        return {false, "Database error."};
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        logger_->log(LogLevel::DEBUG, "<<< Exiting loginUser() - invalid credentials");
        return {false, "Invalid username or password."};
    }
    
    int64_t user_id = sqlite3_column_int64(stmt, 0);
    std::string stored_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    std::string salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    bool is_verified = sqlite3_column_int(stmt, 3) == 1;
    sqlite3_finalize(stmt);

    // Check if user is verified
    if (!is_verified) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting loginUser() - not verified");
        return {false, "Please verify your email before logging in."};
    }

    // Verify password
    logger_->log(LogLevel::DEBUG, "Verifying password...");
    std::string provided_hash = hashPassword(password, salt);
    if (provided_hash != stored_hash) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting loginUser() - invalid password");
        return {false, "Invalid username or password."};
    }

    // Create session
    logger_->log(LogLevel::DEBUG, "Creating session...");
    std::string session_token = generateSessionToken();
    int64_t expires_at = std::time(nullptr) + config_.session_lifetime;

    const char* session_sql = R"(
        INSERT INTO sessions (user_id, token, expires_at)
        VALUES (?, ?, ?)
    )";
    
    rc = sqlite3_prepare_v2(db_, session_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting loginUser() - failed to create session");
        return {false, "Failed to create session."};
    }
    
    sqlite3_bind_int64(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, session_token.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, expires_at);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting loginUser() - failed to create session");
        return {false, "Failed to create session."};
    }

    logger_->log(LogLevel::INFO, "User logged in: " + username);
    logger_->log(LogLevel::DEBUG, "<<< Exiting loginUser() - success");
    
    // Return with proper session token in the new field
    AuthResult result;
    result.success = true;
    result.message = "Login successful";
    result.user_id = user_id;
    result.session_token = session_token;
    return result;
}

SessionInfo AuthManager::validateSession(const std::string& token) {
    logger_->log(LogLevel::DEBUG, ">>> Entering validateSession()");
    
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        SELECT s.user_id, s.expires_at, u.username, u.email 
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ? AND s.expires_at > strftime('%s', 'now')
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting validateSession() - database error");
        return {false, 0, "", ""};
    }
    
    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        logger_->log(LogLevel::DEBUG, "<<< Exiting validateSession() - invalid session");
        return {false, 0, "", ""};
    }
    
    SessionInfo info;
    info.valid = true;
    info.user_id = sqlite3_column_int64(stmt, 0);
    info.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    info.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    
    sqlite3_finalize(stmt);
    
    // Optionally extend session
    if (config_.extend_session_on_activity) {
        extendSession(token);
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting validateSession() - valid session for user: " + info.username);
    return info;
}

void AuthManager::extendSession(const std::string& token) {
    logger_->log(LogLevel::DEBUG, ">>> Entering extendSession()");
    
    const char* sql = R"(
        UPDATE sessions 
        SET expires_at = ? 
        WHERE token = ?
    )";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting extendSession() - prepare failed");
        return;
    }
    
    int64_t new_expires = std::time(nullptr) + config_.session_lifetime;
    sqlite3_bind_int64(stmt, 1, new_expires);
    sqlite3_bind_text(stmt, 2, token.c_str(), -1, SQLITE_STATIC);
    
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting extendSession()");
}

bool AuthManager::logoutUser(const std::string& token) {
    logger_->log(LogLevel::DEBUG, ">>> Entering logoutUser()");
    
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = "DELETE FROM sessions WHERE token = ?";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting logoutUser() - prepare failed");
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    bool success = rc == SQLITE_DONE && sqlite3_changes(db_) > 0;
    logger_->log(LogLevel::DEBUG, "<<< Exiting logoutUser() - success: " + std::to_string(success));
    return success;
}

bool AuthManager::sendVerificationEmail(const std::string& email, const std::string& username,
                                       const std::string& code) {
    logger_->log(LogLevel::DEBUG, ">>> Entering sendVerificationEmail() - email: " + email);
    
    if (config_.smtp_server.empty()) {
        logger_->log(LogLevel::WARNING, "SMTP not configured, skipping email");
        logger_->log(LogLevel::DEBUG, "<<< Exiting sendVerificationEmail() - no SMTP");
        return false;
    }
    
    // Build email
    std::stringstream email_body;
    email_body << "From: " << config_.smtp_from << "\r\n";
    email_body << "To: " << email << "\r\n";
    email_body << "Subject: Verify your account\r\n";
    email_body << "\r\n";
    email_body << "Hello " << username << ",\r\n\r\n";
    email_body << "Your verification code is: " << code << "\r\n\r\n";
    email_body << "This code will expire in 1 hour.\r\n\r\n";
    email_body << "Best regards,\r\nThe Team\r\n";
    
    logger_->log(LogLevel::DEBUG, "Sending email via SendGmail...");
    int res = SendGmail(config_.smtp_from,config_.smtp_password,email,email_body.str()) ; 
    
    if (res != 1) {
        logger_->log(LogLevel::ERROR, "Failed to send email");
        logger_->log(LogLevel::DEBUG, "<<< Exiting sendVerificationEmail() - send failed");
        return false;
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting sendVerificationEmail() - success");
    return true;
}

std::string AuthManager::extractSessionFromCookies(const std::string& cookie_header) {
    logger_->log(LogLevel::DEBUG, ">>> Entering extractSessionFromCookies()");
    
    std::string session_cookie_name = "session=";
    size_t pos = cookie_header.find(session_cookie_name);
    if (pos == std::string::npos) {
        logger_->log(LogLevel::DEBUG, "<<< Exiting extractSessionFromCookies() - no session cookie");
        return "";
    }
    
    pos += session_cookie_name.length();
    size_t end = cookie_header.find(';', pos);
    
    std::string session;
    if (end == std::string::npos) {
        session = cookie_header.substr(pos);
    } else {
        session = cookie_header.substr(pos, end - pos);
    }
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting extractSessionFromCookies() - found session");
    return session;
}

std::string AuthManager::createSessionCookie(const std::string& token) {
    logger_->log(LogLevel::DEBUG, ">>> Entering createSessionCookie()");
    
    std::stringstream cookie;
    cookie << "session=" << token;
    cookie << "; HttpOnly";  // Prevent JavaScript access
    cookie << "; Secure";    // HTTPS only
    cookie << "; SameSite=Strict";  // CSRF protection
    cookie << "; Path=/";
    cookie << "; Max-Age=" << config_.session_lifetime;
    
    logger_->log(LogLevel::DEBUG, "<<< Exiting createSessionCookie()");
    return cookie.str();
}

std::string AuthManager::createLogoutCookie() {
    logger_->log(LogLevel::DEBUG, ">>> Entering createLogoutCookie()");
    logger_->log(LogLevel::DEBUG, "<<< Exiting createLogoutCookie()");
    return "session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
}

} // namespace Auth