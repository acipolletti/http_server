// logger.hpp
#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <fstream>
#include <iostream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3
};

class Logger {
private:
    std::ofstream file_stream;
    bool console_output;
    LogLevel min_level;
    std::mutex log_mutex;

    std::string levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO: return "INFO";
            case LogLevel::WARNING: return "WARNING";
            case LogLevel::ERROR: return "ERROR";
            default: return "UNKNOWN";
        }
    }

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

public:
    Logger(bool console = true) : console_output(console)
    {
        
    }

    void Config(const std::string& filename) {
        min_level = LogLevel::INFO; 
        if (!filename.empty()) {
            file_stream.open(filename, std::ios::app);
            if (!file_stream.is_open()) {
                std::cerr << "Failed to open log file: " << filename << std::endl;
            }
        }
    }

    ~Logger() {
        if (file_stream.is_open()) {
            file_stream.close();
        }
    }

    void set_level(LogLevel level) {
        min_level = level;
    }

    void log(LogLevel level, const std::string& message) {
        if (level < min_level) {
            return;
        }

        std::lock_guard<std::mutex> lock(log_mutex);
        
        std::string timestamp = getCurrentTimestamp();
        std::string level_str = levelToString(level);
        // Get current thread ID
        std::ostringstream thread_stream;
        thread_stream << std::this_thread::get_id();
        std::string thread_id = thread_stream.str();
        
        std::string log_line = "[" + timestamp + "] [" + level_str + "] [Thread: " + thread_id + "] " + message;

        if (console_output) {
            std::cout << log_line << std::endl;
        }

        if (file_stream.is_open()) {
            file_stream << log_line << std::endl;
            file_stream.flush();
        }
    }
};

#endif // LOGGER_HPP
