#include "check_mime_type.hpp"

// Definition of the static member variable
const std::unordered_map<std::string, FileTypeInfo> MimeTypeDetector::mime_map = {
    // Text/Web files
    {"html", {"text/html", false, "/"}},
    {"htm", {"text/html", false, "/"}},
    {"css", {"text/css", false, "/css/"}},
    {"scss", {"text/x-scss", false, "/css/"}},
    {"sass", {"text/x-sass", false, "/css/"}},
    {"js", {"application/javascript", false, "/js/"}},
    {"mjs", {"application/javascript", false, "/js/"}},
    {"ts", {"application/typescript", false, "/js/"}},
    {"jsx", {"text/jsx", false, "/js/"}},
    {"tsx", {"text/tsx", false, "/js/"}},
    {"json", {"application/json", false, "/data/"}},
    {"xml", {"application/xml", false, "/data/"}},
    {"txt", {"text/plain", false, "/docs/"}},
    {"csv", {"text/csv", false, "/data/"}},
    {"md", {"text/markdown", false, "/docs/"}},
    
    // Images
    {"jpg", {"image/jpeg", true, "/images/"}},
    {"jpeg", {"image/jpeg", true, "/images/"}},
    {"png", {"image/png", true, "/images/"}},
    {"gif", {"image/gif", true, "/images/"}},
    {"bmp", {"image/bmp", true, "/images/"}},
    {"ico", {"image/x-icon", true, "/"}},
    {"svg", {"image/svg+xml", false, "/images/"}},
    {"webp", {"image/webp", true, "/images/"}},
    {"tiff", {"image/tiff", true, "/images/"}},
    {"tif", {"image/tiff", true, "/images/"}},
    
    // Audio
    {"mp3", {"audio/mpeg", true, "/audio/"}},
    {"wav", {"audio/wav", true, "/audio/"}},
    {"ogg", {"audio/ogg", true, "/audio/"}},
    {"m4a", {"audio/mp4", true, "/audio/"}},
    {"flac", {"audio/flac", true, "/audio/"}},
    {"aac", {"audio/aac", true, "/audio/"}},
    
    // Video
    {"mp4", {"video/mp4", true, "/video/"}},
    {"avi", {"video/x-msvideo", true, "/video/"}},
    {"mov", {"video/quicktime", true, "/video/"}},
    {"webm", {"video/webm", true, "/video/"}},
    {"mkv", {"video/x-matroska", true, "/video/"}},
    {"flv", {"video/x-flv", true, "/video/"}},
    
    // Documents
    {"pdf", {"application/pdf", true, "/docs/"}},
    {"doc", {"application/msword", true, "/docs/"}},
    {"docx", {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", true, "/docs/"}},
    {"xls", {"application/vnd.ms-excel", true, "/docs/"}},
    {"xlsx", {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", true, "/docs/"}},
    {"ppt", {"application/vnd.ms-powerpoint", true, "/docs/"}},
    {"pptx", {"application/vnd.openxmlformats-officedocument.presentationml.presentation", true, "/docs/"}},
    
    // Archives
    {"zip", {"application/zip", true, "/downloads/"}},
    {"rar", {"application/x-rar-compressed", true, "/downloads/"}},
    {"tar", {"application/x-tar", true, "/downloads/"}},
    {"gz", {"application/gzip", true, "/downloads/"}},
    {"7z", {"application/x-7z-compressed", true, "/downloads/"}},
    
    // Fonts
    {"ttf", {"font/ttf", true, "/fonts/"}},
    {"otf", {"font/otf", true, "/fonts/"}},
    {"woff", {"font/woff", true, "/fonts/"}},
    {"woff2", {"font/woff2", true, "/fonts/"}},
    {"eot", {"application/vnd.ms-fontobject", true, "/fonts/"}}
};