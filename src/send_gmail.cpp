#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <curl/curl.h>

class GmailSender {
private:
    std::string smtp_server = "smtp.gmail.com:587";
    std::string username;
    std::string password;
    
    struct EmailData {
        std::vector<std::string> lines;
        size_t current_line = 0;
    };
    
    static size_t payload_source(char* ptr, size_t size, size_t nmemb, void* userp) {
        auto* email_data = static_cast<EmailData*>(userp);
        
        if ((size == 0) || (nmemb == 0) || (email_data->current_line >= email_data->lines.size())) {
            return 0;
        }
        
        const std::string& line = email_data->lines[email_data->current_line];
        size_t len = line.length();
        
        if (len > size * nmemb) {
            return 0;
        }
        
        std::copy(line.begin(), line.end(), ptr);
        email_data->current_line++;
        
        return len;
    }
    
    std::string get_current_date() const {
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%a, %d %b %Y %H:%M:%S %z");
        return oss.str();
    }

public:
    GmailSender(const std::string& email, const std::string& app_password) 
        : username(email), password(app_password) {}
    
    struct EmailMessage {
        std::string from;
        std::string to;
        std::string subject;
        std::string body;
        std::vector<std::string> cc;
        std::vector<std::string> bcc;
    };
    
    bool send_email(const EmailMessage& message) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            std::cerr << "Failed to initialize CURL" << std::endl;
            return false;
        }
        
        // Unique pointer per cleanup automatico
        std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl_guard(curl, curl_easy_cleanup);
        
        // Costruisci l'email in formato RFC 5322
        EmailData email_data;
        email_data.lines.push_back("Date: " + get_current_date() + "\r\n");
        email_data.lines.push_back("From: " + message.from + "\r\n");
        email_data.lines.push_back("To: " + message.to + "\r\n");
        
        // Aggiungi CC se presenti
        if (!message.cc.empty()) {
            std::string cc_line = "Cc: ";
            for (size_t i = 0; i < message.cc.size(); ++i) {
                cc_line += message.cc[i];
                if (i < message.cc.size() - 1) cc_line += ", ";
            }
            email_data.lines.push_back(cc_line + "\r\n");
        }
        
        email_data.lines.push_back("Subject: " + message.subject + "\r\n");
        email_data.lines.push_back("MIME-Version: 1.0\r\n");
        email_data.lines.push_back("Content-Type: text/plain; charset=UTF-8\r\n");
        email_data.lines.push_back("\r\n"); // Linea vuota tra header e body
        
        // Aggiungi il body dell'email
        std::istringstream body_stream(message.body);
        std::string line;
        while (std::getline(body_stream, line)) {
            email_data.lines.push_back(line + "\r\n");
        }
        
        // Lista destinatari
        curl_slist* recipients = nullptr;
        recipients = curl_slist_append(recipients, message.to.c_str());
        
        for (const auto& cc : message.cc) {
            recipients = curl_slist_append(recipients, cc.c_str());
        }
        
        for (const auto& bcc : message.bcc) {
            recipients = curl_slist_append(recipients, bcc.c_str());
        }
        
        // Configurazione CURL
        curl_easy_setopt(curl, CURLOPT_URL, smtp_server.c_str());
        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
        curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, message.from.c_str());
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
        curl_easy_setopt(curl, CURLOPT_READDATA, &email_data);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); // Imposta a 1L per debug
        
        // Invia l'email
        CURLcode res = curl_easy_perform(curl);
        
        // Cleanup
        curl_slist_free_all(recipients);
        
        if (res != CURLE_OK) {
            std::cerr << "Failed to send email: " << curl_easy_strerror(res) << std::endl;
            return false;
        }
        
        return true;
    }
};

// Esempio di utilizzo
int SendGmail(std::string gmail_address,std::string app_password,std::string send_to,std::string body) {
    // IMPORTANTE: Usa una App Password, non la password normale del tuo account Gmail
    // Vai su: https://myaccount.google.com/apppasswords per generarne una
    
    
    GmailSender sender(gmail_address, app_password);
    
    GmailSender::EmailMessage msg;
    msg.from = gmail_address;
    msg.to = send_to;
    msg.subject = "verify code";
    msg.body = body;
    
    // Opzionale: aggiungi CC e BCC
    // msg.cc.push_back("cc@example.com");
    // msg.bcc.push_back("bcc@example.com");
   
    
    return sender.send_email(msg);
}