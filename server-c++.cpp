#include <iostream>     // For standard C++ I/O (std::cout, std::cerr)
#include <string>       // For std::string
#include <vector>       // For std::vector
#include <fstream>      // For file operations (std::ifstream)
#include <sstream>      // For string stream operations (std::ostringstream)
#include <map>          // For std::map (could be used for MIME types, but if-else is fine too)
#include <algorithm>    // For std::transform, std::tolower (for case-insensitive string ops)

#include <winsock2.h>   // For Windows Sockets API
#include <ws2tcpip.h>   // For InetNtopA, INET_ADDRSTRLEN
#include <windows.h>    // For Windows API functions
#include <direct.h>     // For _mkdir, if needed (CreateDirectory is preferred)
#include <io.h>         // For _access
#include <sys/stat.h>   // For _stat struct and function
#include <time.h>       // For time functions (used in file modification time)
#include <lmcons.h>     // For UNLEN (max username length)
#include <aclapi.h>     // For access control functions
#include <sddl.h>       // For ConvertSidToStringSid
#include <errno.h>      // For strerror(errno)

// Link with Ws2_32.lib implicitly through pragma comment
#pragma comment(lib, "Ws2_32.lib")

// Define constants for the server
#define PORT 8080       // Changed default port to 8080
#define BUFFER_SIZE 8192 // Buffer size for network operations
#define MAX_PATH_LEN 260 // Max path length on Windows

// Define the content directory and icon directory names relative to the executable
#define CONTENT_DIR_NAME "files"
#define ICONS_DIR_NAME "icons"

// Helper for case-insensitive string comparison on Windows
int stricmp_wrapper(const std::string& s1, const std::string& s2) {
    return _stricmp(s1.c_str(), s2.c_str());
}

class WebServer {
public:
    WebServer() {
        // Get the executable's directory to set up base paths
        char server_executable_path[MAX_PATH_LEN];
        GetModuleFileNameA(NULL, server_executable_path, MAX_PATH_LEN);

        char drive[_MAX_DRIVE];
        char dir[_MAX_DIR];
        _splitpath(server_executable_path, drive, dir, NULL, NULL);

        base_dir_for_content_ = std::string(drive) + dir + CONTENT_DIR_NAME + "\\";
        base_dir_for_icons_ = std::string(drive) + dir + ICONS_DIR_NAME + "\\";
    }

    // NEW: Helper function to get the appropriate icon filename based on extension
    std::string get_icon_filename_for_extension(const std::string& file_ext) {
        if (file_ext.empty()) return "file.ico"; // Default for no extension

        // Use _stricmp for case-insensitive comparison
        if (stricmp_wrapper(file_ext, "txt") == 0) return "txt.ico";
        if (stricmp_wrapper(file_ext, "html") == 0 || stricmp_wrapper(file_ext, "htm") == 0) return "page.ico";
        if (stricmp_wrapper(file_ext, "css") == 0) return "css.ico";
        if (stricmp_wrapper(file_ext, "js") == 0) return "js.ico";
        if (stricmp_wrapper(file_ext, "json") == 0) return "json.ico";
        if (stricmp_wrapper(file_ext, "jpg") == 0 || stricmp_wrapper(file_ext, "jpeg") == 0 || stricmp_wrapper(file_ext, "png") == 0 || stricmp_wrapper(file_ext, "gif") == 0) return "image.ico";
        if (stricmp_wrapper(file_ext, "pdf") == 0) return "pdf.ico";
        if (stricmp_wrapper(file_ext, "zip") == 0 || stricmp_wrapper(file_ext, "rar") == 0 || stricmp_wrapper(file_ext, "7z") == 0) return "zip.ico";
        if (stricmp_wrapper(file_ext, "mp3") == 0 || stricmp_wrapper(file_ext, "wav") == 0 || stricmp_wrapper(file_ext, "flac") == 0) return "audio.ico";
        if (stricmp_wrapper(file_ext, "mp4") == 0 || stricmp_wrapper(file_ext, "avi") == 0 || stricmp_wrapper(file_ext, "mkv") == 0) return "video.ico";
        if (stricmp_wrapper(file_ext, "exe") == 0 || stricmp_wrapper(file_ext, "msi") == 0) return "exe.ico";
        if (stricmp_wrapper(file_ext, "doc") == 0 || stricmp_wrapper(file_ext, "docx") == 0) return "doc.ico";
        if (stricmp_wrapper(file_ext, "xml") == 0) return "xml.ico";

        return "file.ico"; // Default icon for unrecognized file types
    }

    // Helper function to get MIME type based on file extension
    std::string get_mime_type(const std::string& file_ext) {
        // Use _stricmp for case-insensitive comparison (Windows-specific)
        if (stricmp_wrapper(file_ext, "html") == 0 || stricmp_wrapper(file_ext, "htm") == 0) return "text/html";
        if (stricmp_wrapper(file_ext, "txt") == 0) return "text/plain";
        if (stricmp_wrapper(file_ext, "css") == 0) return "text/css";
        if (stricmp_wrapper(file_ext, "js") == 0) return "application/javascript";
        if (stricmp_wrapper(file_ext, "json") == 0) return "application/json";
        if (stricmp_wrapper(file_ext, "jpg") == 0 || stricmp_wrapper(file_ext, "jpeg") == 0) return "image/jpeg";
        if (stricmp_wrapper(file_ext, "png") == 0) return "image/png";
        if (stricmp_wrapper(file_ext, "gif") == 0) return "image/gif";
        if (stricmp_wrapper(file_ext, "ico") == 0) return "image/x-icon";
        if (stricmp_wrapper(file_ext, "pdf") == 0) return "application/pdf";
        if (stricmp_wrapper(file_ext, "zip") == 0) return "application/zip";
        if (stricmp_wrapper(file_ext, "mp3") == 0) return "audio/mpeg";
        if (stricmp_wrapper(file_ext, "mp4") == 0) return "video/mp4";
        return "application/octet-stream"; // Default type for unknown files
    }

    // Function to send an HTTP response
    void send_response(SOCKET client_sock, const std::string& status, const std::string& content_type, const std::string& body, long content_length) {
        std::ostringstream header_stream;
        header_stream << "HTTP/1.1 " << status << "\r\n"
                      << "Content-Type: " << content_type << "\r\n"
                      << "Content-Length: " << content_length << "\r\n"
                      << "Connection: close\r\n"
                      << "\r\n";
        std::string header = header_stream.str();

        send(client_sock, header.c_str(), static_cast<int>(header.length()), 0);
        if (!body.empty() && content_length > 0) {
            send(client_sock, body.c_str(), static_cast<int>(content_length), 0);
        }
    }

    // Function to send a file as an HTTP response
    void send_file(SOCKET client_sock, const std::string& filepath, const std::string& content_type, int force_download) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error opening file: " << filepath << std::endl;
            send_response(client_sock, "404 Not Found", "text/plain", "404 Not Found", strlen("404 Not Found"));
            return;
        }

        // Get file size
        file.seekg(0, std::ios::end);
        long file_size = static_cast<long>(file.tellg());
        file.seekg(0, std::ios::beg);

        std::ostringstream header_stream;

        if (force_download) {
            // Extract filename from filepath for Content-Disposition
            size_t last_slash_pos = filepath.find_last_of('\\');
            std::string filename = (last_slash_pos == std::string::npos) ? filepath : filepath.substr(last_slash_pos + 1);

            header_stream << "HTTP/1.1 200 OK\r\n"
                          << "Content-Type: " << content_type << "\r\n"
                          << "Content-Disposition: attachment; filename=\"" << filename << "\"\r\n" // Force download
                          << "Content-Length: " << file_size << "\r\n"
                          << "Connection: close\r\n"
                          << "\r\n";
        } else {
            header_stream << "HTTP/1.1 200 OK\r\n"
                          << "Content-Type: " << content_type << "\r\n"
                          << "Content-Length: " << file_size << "\r\n"
                          << "Connection: close\r\n"
                          << "\r\n";
        }

        std::string header = header_stream.str();
        send(client_sock, header.c_str(), static_cast<int>(header.length()), 0);

        std::vector<char> buffer(BUFFER_SIZE);
        while (file.read(buffer.data(), buffer.size())) {
            send(client_sock, buffer.data(), static_cast<int>(file.gcount()), 0);
        }
        if (file.gcount() > 0) { // Send remaining bytes if any
            send(client_sock, buffer.data(), static_cast<int>(file.gcount()), 0);
        }
    }

    // Function to generate a directory listing as HTML
    void generate_listing(SOCKET client_sock, const std::string& dirpath) {
        WIN32_FIND_DATAA findFileData; // Use WIN32_FIND_DATAA for ANSI strings
        HANDLE hFind;
        std::string searchPath = dirpath + "\\*";
        std::ostringstream listing_stream;

        listing_stream << "<!DOCTYPE html>\n"
                       << "<html><head><title>Directory Listing for " << dirpath << "</title>"
                       << "<style>"
                       << "body { font-family: sans-serif; background-color: #f4f4f4; color: #333; margin: 20px; }"
                       << "h1 { color: #0056b3; }"
                       << "table { width: 90%; border-collapse: collapse; margin-top: 20px; background-color: #fff; box-shadow: 0 0 10px rgba(0,0,0,0.1); }"
                       << "th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }"
                       << "th { background-color: #e2e2e2; }"
                       << "tr:nth-child(even) { background-color: #f9f9f9; }"
                       << "a { text-decoration: none; color: #007bff; }"
                       << "a:hover { text-decoration: underline; }"
                       << ".icon { vertical-align: middle; margin-right: 5px; width: 16px; height: 16px; }"
                       << ".dir { color: #b30000; font-weight: bold; }"
                       << ".file { color: #0056b3; }"
                       << ".action-links a { margin-right: 10px; font-size: 0.9em; }"
                       << "</style>"
                       << "</head><body><h1>Directory Listing for " << dirpath << "</h1><table>"
                       << "<thead><tr><th>Icon</th><th>Name</th><th>Size</th><th>Last Modified</th><th>Actions</th></tr></thead></thead><tbody>";

        // Add ".." (parent directory) link
        listing_stream << "<tr><td><img src=\"/" << ICONS_DIR_NAME << "/up.ico\" class=\"icon\" alt=\"Parent Directory Icon\" width=\"16\" height=\"16\"></td>"
                       << "<td><a href=\"../\" class=\"dir\">..</a></td><td></td><td></td><td></td></tr>";

        hFind = FindFirstFileA(searchPath.c_str(), &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
            std::cerr << "Error opening directory for listing (FindFirstFile): " << GetLastError() << std::endl;
            send_response(client_sock, "500 Internal Server Error", "text/plain", "500 Internal Server Error", strlen("500 Internal Server Error"));
            return;
        }

        do {
            // Skip current and parent directory entries
            if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0) {
                continue;
            }

            std::string current_file_name = findFileData.cFileName;
            std::string fullpath = dirpath + "\\" + current_file_name;

            std::string size_str;
            std::string last_mod_str;
            SYSTEMTIME stUTC, stLocal;
            FILETIME ftLastWriteTime;

            ftLastWriteTime = findFileData.ftLastWriteTime;
            FileTimeToSystemTime(&ftLastWriteTime, &stUTC);
            SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

            char time_buf[64];
            snprintf(time_buf, sizeof(time_buf), "%04d-%02d-%02d %02d:%02d:%02d",
                     stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                     stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
            last_mod_str = time_buf;

            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                size_str = "-";
                listing_stream << "<tr><td><img src=\"/" << ICONS_DIR_NAME << "/dir.ico\" class=\"icon\" alt=\"Directory Icon\" width=\"16\" height=\"16\"></td>"
                               << "<td><a href=\"" << current_file_name << "/\" class=\"dir\">" << current_file_name << "/</a></td><td>" << size_str << "</td><td>" << last_mod_str << "</td><td></td></tr>";
            } else {
                long long file_size = (static_cast<long long>(findFileData.nFileSizeHigh) << 32) | findFileData.nFileSizeLow;
                size_str = std::to_string(file_size) + " bytes";

                size_t ext_pos = current_file_name.rfind('.');
                std::string file_ext = (ext_pos == std::string::npos) ? "" : current_file_name.substr(ext_pos + 1);
                std::string icon_to_use = get_icon_filename_for_extension(file_ext);

                std::string icon_path_html = "/" + std::string(ICONS_DIR_NAME) + "/" + icon_to_use;

                listing_stream << "<tr><td><img src=\"" << icon_path_html << "\" class=\"icon\" alt=\"File Icon\" width=\"16\" height=\"16\"></td>"
                               << "<td><a href=\"" << current_file_name << "\" class=\"file\">" << current_file_name << "</a></td><td>" << size_str << "</td><td>" << last_mod_str << "</td><td class=\"action-links\">";

                int is_text_file = (ext_pos != std::string::npos && stricmp_wrapper(file_ext, "txt") == 0);

                if (is_text_file) {
                    listing_stream << "<a href=\"" << current_file_name << "\">View</a> | <a href=\"" << current_file_name << "?download=1\">Download</a>";
                } else {
                    listing_stream << "<a href=\"" << current_file_name << "\">Open</a>";
                }
                listing_stream << "</td></tr>";
            }
        } while (FindNextFileA(hFind, &findFileData) != 0);

        FindClose(hFind);

        listing_stream << "</tbody></table></body></html>";

        std::string html_body = listing_stream.str();
        send_response(client_sock, "200 OK", "text/html", html_body, static_cast<long>(html_body.length()));
    }


    // Function to handle a single client request
    void handle_client(SOCKET client_sock) {
        std::vector<char> request_buffer(BUFFER_SIZE);
        int bytes_received = recv(client_sock, request_buffer.data(), static_cast<int>(request_buffer.size()) - 1, 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                std::cerr << "Client disconnected." << std::endl;
            } else {
                std::cerr << "Failed to receive data: " << WSAGetLastError() << std::endl;
            }
            closesocket(client_sock);
            return;
        }
        request_buffer[bytes_received] = '\0';
        std::string request(request_buffer.data());

        std::cout << "Received request:\n" << request << std::endl;

        std::istringstream iss(request);
        std::string method, path_with_query, http_version_str;
        iss >> method >> path_with_query >> http_version_str;

        if (method.empty() || path_with_query.empty() || http_version_str.empty()) {
            send_response(client_sock, "400 Bad Request", "text/plain", "Bad Request", strlen("Bad Request"));
            closesocket(client_sock);
            return;
        }

        if (stricmp_wrapper(method, "GET") != 0) {
            send_response(client_sock, "501 Not Implemented", "text/plain", "Not Implemented", strlen("Not Implemented"));
            closesocket(client_sock);
            return;
        }

        int force_download = 0;
        std::string clean_path = path_with_query;
        size_t query_pos = path_with_query.find('?');
        if (query_pos != std::string::npos) {
            clean_path = path_with_query.substr(0, query_pos);
            if (path_with_query.substr(query_pos).find("download=1") != std::string::npos) {
                force_download = 1;
            }
        }

        std::string windows_path = clean_path;
        for (char& c : windows_path) {
            if (c == '/') {
                c = '\\';
            }
        }

        std::string target_file_path;

        if (windows_path == "\\") {
            target_file_path = base_dir_for_content_;
        } else if (windows_path.length() > 1 && windows_path[0] == '\\' &&
                   stricmp_wrapper(windows_path.substr(1, strlen(ICONS_DIR_NAME)), ICONS_DIR_NAME) == 0) {
            target_file_path = base_dir_for_icons_ + windows_path.substr(1 + strlen(ICONS_DIR_NAME));
        } else if (windows_path.length() > 1 && windows_path[0] == '\\' &&
                   stricmp_wrapper(windows_path.substr(1, strlen(CONTENT_DIR_NAME)), CONTENT_DIR_NAME) == 0) {
            target_file_path = base_dir_for_content_ + windows_path.substr(1 + strlen(CONTENT_DIR_NAME));
        } else {
            target_file_path = base_dir_for_content_ + windows_path.substr(1);
        }

        char safe_path_buf[MAX_PATH_LEN];
        if (_fullpath(safe_path_buf, target_file_path.c_str(), MAX_PATH_LEN) == NULL) {
            std::cerr << "Error resolving full path for " << target_file_path << ": " << strerror(errno) << " (might not exist or invalid)" << std::endl;
            send_response(client_sock, "404 Not Found", "text/plain", "404 Not Found", strlen("404 Not Found"));
            closesocket(client_sock);
            return;
        }
        std::string safe_path = safe_path_buf;

        // --- SECURITY CHECK ---
        char full_content_base_dir_resolved_buf[MAX_PATH_LEN];
        char full_icons_base_dir_resolved_buf[MAX_PATH_LEN];

        if (_fullpath(full_content_base_dir_resolved_buf, base_dir_for_content_.c_str(), MAX_PATH_LEN) == NULL ||
            _fullpath(full_icons_base_dir_resolved_buf, base_dir_for_icons_.c_str(), MAX_PATH_LEN) == NULL) {
            std::cerr << "Error resolving base content/icons directory paths for security check." << std::endl;
            send_response(client_sock, "500 Internal Server Error", "text/plain", "500 Internal Server Error", strlen("500 Internal Server Error"));
            closesocket(client_sock);
            return;
        }

        std::string full_content_base_dir_resolved = full_content_base_dir_resolved_buf;
        std::string full_icons_base_dir_resolved = full_icons_base_dir_resolved_buf;

        if (full_content_base_dir_resolved.back() != '\\') {
            full_content_base_dir_resolved += "\\";
        }
        if (full_icons_base_dir_resolved.back() != '\\') {
            full_icons_base_dir_resolved += "\\";
        }

        if (!(safe_path.rfind(full_content_base_dir_resolved, 0) == 0 || // Starts with
              safe_path.rfind(full_icons_base_dir_resolved, 0) == 0)) {
            std::cerr << "Attempted directory traversal: " << safe_path << " (Content base: " << full_content_base_dir_resolved << ", Icons base: " << full_icons_base_dir_resolved << ")" << std::endl;
            send_response(client_sock, "403 Forbidden", "text/plain", "Forbidden", strlen("Forbidden"));
            closesocket(client_sock);
            return;
        }
        // --- END SECURITY CHECK ---

        struct _stat path_stat;
        if (_stat(safe_path.c_str(), &path_stat) == -1) {
            std::cerr << "_stat error for path " << safe_path << ": " << GetLastError() << std::endl;
            send_response(client_sock, "404 Not Found", "text/plain", "404 Not Found", strlen("404 Not Found"));
            closesocket(client_sock);
            return;
        }

        if ((path_stat.st_mode & _S_IFDIR)) {
            std::string index_html_path = safe_path + "\\index.html";
            struct _stat index_stat;
            if (_stat(index_html_path.c_str(), &index_stat) == 0 && (index_stat.st_mode & _S_IFREG)) {
                send_file(client_sock, index_html_path, "text/html", 0);
            } else {
                generate_listing(client_sock, safe_path);
            }
        } else if ((path_stat.st_mode & _S_IFREG)) {
            size_t file_ext_pos = clean_path.rfind('.');
            std::string file_ext = (file_ext_pos == std::string::npos) ? "" : clean_path.substr(file_ext_pos + 1);
            std::string content_type = get_mime_type(file_ext);
            send_file(client_sock, safe_path, content_type, force_download);
        } else {
            send_response(client_sock, "403 Forbidden", "text/plain", "Forbidden", strlen("Forbidden"));
        }

        closesocket(client_sock);
    }

    void run() {
        WSADATA wsaData;
        SOCKET server_sock, client_sock;
        struct sockaddr_in server_addr, client_addr;
        int client_len = sizeof(client_addr);

        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
            return;
        }

        server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_sock == INVALID_SOCKET) {
            std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return;
        }

        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(PORT);

        if (bind(server_sock, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
            std::cerr << "Socket binding failed: " << WSAGetLastError() << std::endl;
            closesocket(server_sock);
            WSACleanup();
            return;
        }

        if (listen(server_sock, SOMAXCONN) == SOCKET_ERROR) {
            std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
            closesocket(server_sock);
            WSACleanup();
            return;
        }

        std::cout << "File server running on http://localhost:" << PORT << std::endl;
        std::cout << "Serving content from: " << base_dir_for_content_ << std::endl;
        std::cout << "Serving icons from: " << base_dir_for_icons_ << std::endl;

        // Check and create content and icon directories if they don't exist
        if (CreateDirectoryA(base_dir_for_content_.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
            std::cout << "Content directory exists or created: " << base_dir_for_content_ << std::endl;
        } else {
            std::cerr << "Failed to create content directory " << base_dir_for_content_ << ": " << GetLastError() << std::endl;
        }
        if (CreateDirectoryA(base_dir_for_icons_.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
            std::cout << "Icons directory exists or created: " << base_dir_for_icons_ << std::endl;
        } else {
            std::cerr << "Failed to create icons directory " << base_dir_for_icons_ << ": " << GetLastError() << std::endl;
        }

        BOOL isAdmin = FALSE;
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        PSID AdministratorsGroup;
        if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                     DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                     &AdministratorsGroup)) {
            if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin)) {
                isAdmin = FALSE;
            }
            FreeSid(AdministratorsGroup);
        }
        if (!isAdmin) {
            std::cout << "WARNING: Server is not running with administrative privileges. Directory creation or binding to privileged ports (like 80) might fail." << std::endl;
        }

        while (true) {
            std::cout << "Waiting for connections..." << std::endl;
            client_sock = accept(server_sock, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
            if (client_sock == INVALID_SOCKET) {
                std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
                continue;
            }

            char client_ip[INET_ADDRSTRLEN];
            if (InetNtopA(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN) == NULL) {
                strcpy(client_ip, "Unknown");
            }
            std::cout << "Accepted connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;

            handle_client(client_sock);
        }

        closesocket(server_sock);
        WSACleanup();
    }

private:
    std::string base_dir_for_content_;
    std::string base_dir_for_icons_;
};

int main() {
    WebServer server;
    server.run();
    return 0;
}