#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <unordered_map>
#include <random>

// Useremo cpp-httplib (https://github.com/yhirose/cpp-httplib)
// È una libreria header-only, quindi basta includere httplib.h
#include "httplib.h"

// Per il parsing JSON useremo nlohmann/json (https://github.com/nlohmann/json)

#include "nlohmann/json.hpp"
#include "check_mime_type.hpp"

class FileServer {
private:
    std::string root_path_;
    httplib::Server server_;
    
    // Funzione per generare ID univoco per upload
    std::string generate_upload_id() {
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        
        // Genera parte random
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 9999);
        
        std::stringstream ss;
        ss << "upload_" << timestamp << "_" << dis(gen);
        return ss.str();
    }
    
    // Funzione per verificare che il percorso sia sicuro (no path traversal)
    bool is_path_safe(const std::string& path) {
        // Risolvi il percorso assoluto
        fs::path requested = fs::path(root_path_) / path;
        fs::path resolved = fs::canonical(requested.parent_path()) / requested.filename();
        fs::path root_canonical = fs::canonical(root_path_);
        
        // Verifica che il percorso risolto sia dentro la root
        return resolved.string().find(root_canonical.string()) == 0;
    }
    
    // Converti timestamp del file in stringa
    std::string file_time_to_string(const fs::file_time_type& ftime) {
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        
        std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
        std::tm* gmt = std::gmtime(&tt);
        
        std::stringstream buffer;
        buffer << std::put_time(gmt, "%Y-%m-%d");
        return buffer.str();
    }
    
    // Ottieni informazioni su un file/directory
    json get_file_info(const fs::directory_entry& entry) {
        json file_info;
        file_info["name"] = entry.path().filename().string();
        
        if (entry.is_directory()) {
            file_info["type"] = "folder";
            file_info["size"] = "-";
        } else {
            file_info["type"] = "file";
            file_info["size"] = entry.file_size();
        }
        
        file_info["date"] = file_time_to_string(entry.last_write_time());
        
        return file_info;
    }
    
public:
    FileServer(const std::string& root_path, int port = 8080) 
        : root_path_(fs::absolute(root_path).string()) {
        
        // Verifica che la directory root esista
        if (!fs::exists(root_path_) || !fs::is_directory(root_path_)) {
            throw std::runtime_error("Root path non valido o non è una directory");
        }
        
        setup_routes();
        std::cout << "Server configurato sulla porta " << port << std::endl;
        std::cout << "Root directory: " << root_path_ << std::endl;
    }
    
    void setup_routes() {
        // Middleware per CORS
        server_.set_post_routing_handler([](const httplib::Request& req, httplib::Response& res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            res.set_header("Access-Control-Allow-Headers", "Content-Type");
        });
        
        // OPTIONS per CORS preflight
        server_.Options(".*", [](const httplib::Request& req, httplib::Response& res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            res.set_header("Access-Control-Allow-Headers", "Content-Type");
            res.status = 204;
        });
        
        // GET /api/files - Lista file in una directory
        server_.Get("/api/files", [this](const httplib::Request& req, httplib::Response& res) {
            std::string path = req.get_param_value("path");
            if (path.empty()) path = "/";
            
            // Rimuovi slash iniziale se presente
            if (path.front() == '/') path = path.substr(1);
            
            if (!is_path_safe(path)) {
                res.status = 403;
                res.set_content("{\"error\":\"Accesso negato\"}", "application/json");
                return;
            }
            
            fs::path full_path = fs::path(root_path_) / path;
            
            if (!fs::exists(full_path) || !fs::is_directory(full_path)) {
                res.status = 404;
                res.set_content("{\"error\":\"Directory non trovata\"}", "application/json");
                return;
            }
            
            json response;
            json files = json::array();
            
            try {
                for (const auto& entry : fs::directory_iterator(full_path)) {
                    files.push_back(get_file_info(entry));
                }
                
                response["files"] = files;
                response["path"] = "/" + path;
                
                res.set_content(response.dump(), "application/json");
            } catch (const std::exception& e) {
                res.status = 500;
                res.set_content("{\"error\":\"" + std::string(e.what()) + "\"}", "application/json");
            }
        });
        
        // GET /api/download - Download di un file con supporto Range/Chunked
        // This also handles HEAD requests by checking the method
        server_.Get("/api/download", [this](const httplib::Request& req, httplib::Response& res) {
            std::string path = req.get_param_value("path");
            
            if (!is_path_safe(path)) {
                res.status = 403;
                if (req.method != "HEAD") {
                    res.set_content("{\"error\":\"Accesso negato\"}", "application/json");
                }
                return;
            }
            
            fs::path full_path = fs::path(root_path_) / path;
            
            if (!fs::exists(full_path) || !fs::is_regular_file(full_path)) {
                res.status = 404;
                if (req.method != "HEAD") {
                    res.set_content("{\"error\":\"File non trovato\"}", "application/json");
                }
                return;
            }
            
            // Ottieni la dimensione del file
            auto file_size = fs::file_size(full_path);
            
            // Se è una richiesta HEAD, ritorna solo gli headers
            if (req.method == "HEAD") {
                res.set_header("Accept-Ranges", "bytes");
                res.set_header("Content-Length", std::to_string(file_size));
                res.set_header("Content-Type", "application/octet-stream");
                res.status = 200;
                return;
            }
            
            // Il resto del codice per GET continua come prima...
            // Gestione Range headers per download parziali
            std::string range_header = req.get_header_value("Range");
            size_t start = 0;
            size_t end = file_size - 1;
            
            if (!range_header.empty() && range_header.find("bytes=") == 0) {
                // Parse del range header (formato: bytes=start-end)
                std::string range = range_header.substr(6);
                size_t dash_pos = range.find('-');
                
                if (dash_pos != std::string::npos) {
                    std::string start_str = range.substr(0, dash_pos);
                    std::string end_str = range.substr(dash_pos + 1);
                    
                    if (!start_str.empty()) {
                        start = std::stoull(start_str);
                    }
                    if (!end_str.empty()) {
                        end = std::stoull(end_str);
                    }
                }
                
                // Validazione del range
                if (start > end || end >= file_size) {
                    res.status = 416; // Range Not Satisfiable
                    res.set_header("Content-Range", "bytes */" + std::to_string(file_size));
                    return;
                }
                
                // Imposta status 206 per contenuto parziale
                res.status = 206;
                res.set_header("Content-Range", 
                    "bytes " + std::to_string(start) + "-" + 
                    std::to_string(end) + "/" + std::to_string(file_size));
            }
            
            // Calcola la dimensione del contenuto da inviare
            size_t content_length = end - start + 1;
            
            // Imposta headers
            res.set_header("Accept-Ranges", "bytes");
            res.set_header("Content-Length", std::to_string(content_length));
            res.set_header("Content-Type", "application/octet-stream");
            res.set_header("Content-Disposition", 
                          "attachment; filename=\"" + full_path.filename().string() + "\"");
            
            // Stream del file usando un content provider
            res.set_content_provider(
                content_length,
                "application/octet-stream",
                [full_path, start, content_length](size_t offset, size_t length, httplib::DataSink& sink) {
                    std::ifstream file(full_path, std::ios::binary);
                    if (!file) return false;
                    
                    // Posiziona il file all'offset corretto
                    file.seekg(start + offset);
                    
                    // Buffer per la lettura (64KB)
                    const size_t buffer_size = 65536;
                    std::vector<char> buffer(buffer_size);
                    
                    size_t remaining = std::min(length, content_length - offset);
                    
                    while (remaining > 0 && file.good()) {
                        size_t to_read = std::min(buffer_size, remaining);
                        file.read(buffer.data(), to_read);
                        size_t read = file.gcount();
                        
                        if (read > 0) {
                            sink.write(buffer.data(), read);
                            remaining -= read;
                        } else {
                            break;
                        }
                    }
                    
                    return file.good() || file.eof();
                }
            );
        });
        
        // POST /api/upload/init - Inizializza un upload chunked
        server_.Post("/api/upload/init", [this](const httplib::Request& req, httplib::Response& res) {
            json request_data = json::parse(req.body);
            std::string path = request_data["path"];
            std::string filename = request_data["filename"];
            size_t total_size = request_data["total_size"];
            
            if (!is_path_safe(path)) {
                res.status = 403;
                res.set_content("{\"error\":\"Accesso negato\"}", "application/json");
                return;
            }
            
            // Genera un ID univoco per l'upload
            std::string upload_id = generate_upload_id();
            
            // Crea directory temporanea per i chunks
            fs::path temp_dir = fs::temp_directory_path() / "uploads" / upload_id;
            fs::create_directories(temp_dir);
            
            // Salva metadata dell'upload
            json metadata;
            metadata["filename"] = filename;
            metadata["path"] = path;
            metadata["total_size"] = total_size;
            metadata["uploaded_size"] = 0;
            metadata["chunks"] = json::array();
            metadata["created_at"] = std::chrono::system_clock::now().time_since_epoch().count();
            
            std::ofstream meta_file(temp_dir / "metadata.json");
            meta_file << metadata.dump(2);
            meta_file.close();
            
            json response;
            response["upload_id"] = upload_id;
            response["chunk_size"] = 1048576; // 1MB chunks consigliati
            
            res.set_content(response.dump(), "application/json");
        });
        
        // POST /api/upload/chunk - Upload di un singolo chunk
        server_.Post("/api/upload/chunk", [this](const httplib::Request& req, httplib::Response& res) {
            std::string upload_id = req.get_param_value("upload_id");
            std::string chunk_index_str = req.get_param_value("chunk_index");
            
            if (upload_id.empty() || chunk_index_str.empty()) {
                res.status = 400;
                res.set_content("{\"error\":\"Parametri mancanti\"}", "application/json");
                return;
            }
            
            int chunk_index = std::stoi(chunk_index_str);
            
            // Verifica che l'upload esista
            fs::path temp_dir = fs::temp_directory_path() / "uploads" / upload_id;
            fs::path meta_path = temp_dir / "metadata.json";
            
            if (!fs::exists(meta_path)) {
                res.status = 404;
                res.set_content("{\"error\":\"Upload non trovato\"}", "application/json");
                return;
            }
            
            // Leggi metadata
            std::ifstream meta_file(meta_path);
            json metadata = json::parse(meta_file);
            meta_file.close();
            
            // Trova il file chunk nei multipart data
            if (req.files.empty()) {
                res.status = 400;
                res.set_content("{\"error\":\"Nessun chunk ricevuto\"}", "application/json");
                return;
            }
            
            const auto& chunk_file = req.files.begin()->second;
            
            // Salva il chunk
            fs::path chunk_path = temp_dir / ("chunk_" + std::to_string(chunk_index));
            std::ofstream chunk_out(chunk_path, std::ios::binary);
            chunk_out.write(chunk_file.content.data(), chunk_file.content.size());
            chunk_out.close();
            
            // Aggiorna metadata
            json chunk_info;
            chunk_info["index"] = chunk_index;
            chunk_info["size"] = chunk_file.content.size();
            metadata["chunks"].push_back(chunk_info);
            metadata["uploaded_size"] = metadata["uploaded_size"].get<size_t>() + chunk_file.content.size();
            
            std::ofstream meta_out(meta_path);
            meta_out << metadata.dump(2);
            meta_out.close();
            
            json response;
            response["chunk_index"] = chunk_index;
            response["uploaded_size"] = metadata["uploaded_size"];
            response["total_size"] = metadata["total_size"];
            
            res.set_content(response.dump(), "application/json");
        });
        
        // POST /api/upload/complete - Completa l'upload e assembla i chunks
        server_.Post("/api/upload/complete", [this](const httplib::Request& req, httplib::Response& res) {
            json request_data = json::parse(req.body);
            std::string upload_id = request_data["upload_id"];
            
            fs::path temp_dir = fs::temp_directory_path() / "uploads" / upload_id;
            fs::path meta_path = temp_dir / "metadata.json";
            
            if (!fs::exists(meta_path)) {
                res.status = 404;
                res.set_content("{\"error\":\"Upload non trovato\"}", "application/json");
                return;
            }
            
            // Leggi metadata
            std::ifstream meta_file(meta_path);
            json metadata = json::parse(meta_file);
            meta_file.close();
            
            std::string filename = metadata["filename"];
            std::string path = metadata["path"];
            
            if (!is_path_safe(path)) {
                res.status = 403;
                res.set_content("{\"error\":\"Accesso negato\"}", "application/json");
                return;
            }
            
            fs::path upload_dir = fs::path(root_path_) / path;
            fs::path final_path = upload_dir / filename;
            
            // Assembla i chunks
            std::ofstream final_file(final_path, std::ios::binary);
            if (!final_file) {
                res.status = 500;
                res.set_content("{\"error\":\"Impossibile creare il file finale\"}", "application/json");
                return;
            }
            
            // Ordina i chunks per indice
            std::vector<json> chunks = metadata["chunks"];
            std::sort(chunks.begin(), chunks.end(), 
                [](const json& a, const json& b) {
                    return a["index"] < b["index"];
                });
            
            // Copia ogni chunk nel file finale
            for (const auto& chunk : chunks) {
                int index = chunk["index"];
                fs::path chunk_path = temp_dir / ("chunk_" + std::to_string(index));
                
                if (!fs::exists(chunk_path)) {
                    final_file.close();
                    fs::remove(final_path);
                    res.status = 500;
                    res.set_content("{\"error\":\"Chunk mancante: " + std::to_string(index) + "\"}", 
                                   "application/json");
                    return;
                }
                
                std::ifstream chunk_file(chunk_path, std::ios::binary);
                final_file << chunk_file.rdbuf();
                chunk_file.close();
            }
            
            final_file.close();
            
            // Verifica la dimensione finale
            if (fs::file_size(final_path) != metadata["total_size"]) {
                fs::remove(final_path);
                res.status = 500;
                res.set_content("{\"error\":\"Dimensione file non corretta\"}", "application/json");
                return;
            }
            
            // Pulisci i file temporanei
            fs::remove_all(temp_dir);
            
            json response;
            response["filename"] = filename;
            response["path"] = (fs::path(path) / filename).string();
            response["size"] = metadata["total_size"];
            
            res.set_content(response.dump(), "application/json");
        });
        
        // GET /api/upload/status - Verifica lo stato di un upload
        server_.Get("/api/upload/status", [this](const httplib::Request& req, httplib::Response& res) {
            std::string upload_id = req.get_param_value("upload_id");
            
            fs::path temp_dir = fs::temp_directory_path() / "uploads" / upload_id;
            fs::path meta_path = temp_dir / "metadata.json";
            
            if (!fs::exists(meta_path)) {
                res.status = 404;
                res.set_content("{\"error\":\"Upload non trovato\"}", "application/json");
                return;
            }
            
            std::ifstream meta_file(meta_path);
            json metadata = json::parse(meta_file);
            
            json response;
            response["upload_id"] = upload_id;
            response["filename"] = metadata["filename"];
            response["total_size"] = metadata["total_size"];
            response["uploaded_size"] = metadata["uploaded_size"];
            response["chunks_received"] = metadata["chunks"].size();
            response["progress"] = (metadata["uploaded_size"].get<double>() / 
                                   metadata["total_size"].get<double>()) * 100;
            
            res.set_content(response.dump(), "application/json");
        });
        
        // POST /api/upload - Upload standard (mantieni per retrocompatibilità con file piccoli)
        server_.Post("/api/upload", [this](const httplib::Request& req, httplib::Response& res) {
            std::string path = req.get_param_value("path");
            if (path.empty()) path = "/";
            
            if (!is_path_safe(path)) {
                res.status = 403;
                res.set_content("{\"error\":\"Accesso negato\"}", "application/json");
                return;
            }
            
            fs::path upload_dir = fs::path(root_path_) / path;
            
            if (!fs::exists(upload_dir) || !fs::is_directory(upload_dir)) {
                res.status = 404;
                res.set_content("{\"error\":\"Directory non trovata\"}", "application/json");
                return;
            }
            
            json response;
            json uploaded_files = json::array();
            
            // Processa ogni file caricato
            for (const auto& file : req.files) {
                const auto& upload = file.second;
                fs::path file_path = upload_dir / upload.filename;
                
                // Salva il file
                std::ofstream ofs(file_path, std::ios::binary);
                if (ofs) {
                    ofs.write(upload.content.data(), upload.content.size());
                    ofs.close();
                    
                    json file_info;
                    file_info["name"] = upload.filename;
                    file_info["size"] = upload.content.size();
                    uploaded_files.push_back(file_info);
                }
            }
            
            response["uploaded"] = uploaded_files;
            res.set_content(response.dump(), "application/json");
        });
        
        // POST /api/mkdir - Crea una nuova directory
        server_.Post("/api/mkdir", [this](const httplib::Request& req, httplib::Response& res) {
            json request_data = json::parse(req.body);
            std::string path = request_data["path"];
            std::string name = request_data["name"];
            
            if (!is_path_safe(path)) {
                res.status = 403;
                res.set_content("{\"error\":\"Accesso negato\"}", "application/json");
                return;
            }
            
            fs::path new_dir = fs::path(root_path_) / path / name;
            
            try {
                if (fs::exists(new_dir)) {
                    res.status = 409;
                    res.set_content("{\"error\":\"La directory esiste già\"}", "application/json");
                    return;
                }
                
                fs::create_directory(new_dir);
                res.set_content("{\"success\":true}", "application/json");
            } catch (const std::exception& e) {
                res.status = 500;
                res.set_content("{\"error\":\"" + std::string(e.what()) + "\"}", "application/json");
            }
        });
        
        // PUT /api/rename - Rinomina file o directory
        server_.Put("/api/rename", [this](const httplib::Request& req, httplib::Response& res) {
            json request_data = json::parse(req.body);
            std::string old_path = request_data["old_path"];
            std::string new_name = request_data["new_name"];
            
            if (!is_path_safe(old_path)) {
                res.status = 403;
                res.set_content("{\"error\":\"Accesso negato\"}", "application/json");
                return;
            }
            
            fs::path old_full_path = fs::path(root_path_) / old_path;
            fs::path new_full_path = old_full_path.parent_path() / new_name;
            
            try {
                if (!fs::exists(old_full_path)) {
                    res.status = 404;
                    res.set_content("{\"error\":\"File non trovato\"}", "application/json");
                    return;
                }
                
                if (fs::exists(new_full_path)) {
                    res.status = 409;
                    res.set_content("{\"error\":\"Un file con questo nome esiste già\"}", "application/json");
                    return;
                }
                
                fs::rename(old_full_path, new_full_path);
                res.set_content("{\"success\":true}", "application/json");
            } catch (const std::exception& e) {
                res.status = 500;
                res.set_content("{\"error\":\"" + std::string(e.what()) + "\"}", "application/json");
            }
        });
        
        // DELETE /api/delete - Elimina file o directory
        server_.Delete("/api/delete", [this](const httplib::Request& req, httplib::Response& res) {
            std::string path = req.get_param_value("path");
            
            if (!is_path_safe(path)) {
                res.status = 403;
                res.set_content("{\"error\":\"Accesso negato\"}", "application/json");
                return;
            }
            
            fs::path full_path = fs::path(root_path_) / path;
            
            try {
                if (!fs::exists(full_path)) {
                    res.status = 404;
                    res.set_content("{\"error\":\"File non trovato\"}", "application/json");
                    return;
                }
                
                if (fs::is_directory(full_path)) {
                    fs::remove_all(full_path);  // Rimuove ricorsivamente
                } else {
                    fs::remove(full_path);
                }
                
                res.set_content("{\"success\":true}", "application/json");
            } catch (const std::exception& e) {
                res.status = 500;
                res.set_content("{\"error\":\"" + std::string(e.what()) + "\"}", "application/json");
            }
        });
        
        // Serve file statici con gestione MIME types personalizzata
        server_.Get("/.*", [this](const httplib::Request& req, httplib::Response& res) {
            // Se il path inizia con /api, lascia che le altre route lo gestiscano
            if (req.path.find("/api/") == 0) {
                res.status = 404;
                return;
            }
            
            std::string file_path;
            
            // Se è la root o una directory, serve index.html
            if (req.path == "/" || req.path.empty()) {
                file_path = "./public/index.html";
            } else {
                // Usa la funzione find_file per cercare il file nelle possibili locazioni
                file_path = MimeTypeDetector::find_file(req.path, "./public");
                
                // Se non trovato e potrebbe essere una directory, prova con index.html
                if (file_path.empty()) {
                    std::string potential_index = "./public" + req.path + "/index.html";
                    if (fs::exists(potential_index) && fs::is_regular_file(potential_index)) {
                        file_path = potential_index;
                    }
                }
            }
            
            // Se il file non è stato trovato
            if (file_path.empty()) {
                res.status = 404;
                res.set_content("<h1>404 - File Not Found</h1>", "text/html");
                return;
            }
            
            // Leggi il file
            std::ifstream file(file_path, std::ios::binary);
            if (!file) {
                res.status = 500;
                res.set_content("<h1>500 - Internal Server Error</h1>", "text/html");
                return;
            }
            
            std::string content((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
            
            // Determina il MIME type
            std::string mime_type = MimeTypeDetector::get_mime_type(req.path);
            
            // Imposta headers di cache per file statici
            if (MimeTypeDetector::is_binary(req.path)) {
                res.set_header("Cache-Control", "public, max-age=3600");
            } else {
                res.set_header("Cache-Control", "no-cache");
            }
            
            // Imposta la risposta
            res.set_content(content, mime_type);
        });
    }
    
    void start(int port = 8080) {
        std::cout << "Server in ascolto su http://localhost:" << port << std::endl;
        server_.listen("0.0.0.0", port);
    }
};

int main(int argc, char* argv[]) {
    try {
        // Directory root di default
        std::string root_dir = ".";
        int port = 8080;
        
        // Parse argomenti command line
        if (argc > 1) {
            root_dir = argv[1];
        }
        if (argc > 2) {
            port = std::stoi(argv[2]);
        }
        
        FileServer server(root_dir, port);
        server.start(port);
        
    } catch (const std::exception& e) {
        std::cerr << "Errore: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}