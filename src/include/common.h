#ifndef COMMON_HPP
#define COMMON_HPP
struct SSLConfig {
    std::string cert_path;
    std::string key_path;
};


// Updated ServerConfig to include authentication settings
struct ServerConfig {
    std::string host;
    int port;
    int http_port;
    bool enable_http;
    int threads;
    int timeout;
    SSLConfig ssl;

    struct Logging {
        LogLevel level;
        std::string file;
        bool console_output;
    } logging;
    
    // Authentication configuration
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
        struct Response {
            int status;
            std::string content_type;
            std::string body;
        } response;
    };

    std::vector<Route> routes;
};

#endif // COMMON_HPP

