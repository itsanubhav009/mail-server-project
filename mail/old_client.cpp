#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <regex>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <iterator>
#include <vector>
#include <random>


namespace fs = std::filesystem;

using namespace std;
#define BUFFER_SIZE 1024


std::string base64_encode(const std::string& data) {
    static const std::string base64_chars = 
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "abcdefghijklmnopqrstuvwxyz"
                 "0123456789+/";

    std::string encoded_string;
    int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded_string.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) encoded_string.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded_string.size() % 4) encoded_string.push_back('=');
    return encoded_string;
}

bool validate_user_data(const std::string& username, const std::string& password) {
    // Simple regex to validate email format
    const std::regex email_regex(R"((\w+)(\.{1})?(\w*)@(\w+)(\.\w+)+)");

    if (!std::regex_match(username, email_regex)) {
        std::cerr << "Invalid email format." << std::endl;
        return false;
    }

    if (password.length() < 6) {
        std::cerr << "Password should be at least 6 characters long." << std::endl;
        return false;
    }

    return true;
}
void send_data_in_chunks(int sock, const std::string &data) {
    size_t total_size = data.size();
    size_t bytes_sent = 0;

    while (bytes_sent < total_size) {
        size_t chunk_size = std::min(static_cast<size_t>(BUFFER_SIZE), total_size - bytes_sent);
        std::string chunk = data.substr(bytes_sent, chunk_size);
        send(sock, chunk.c_str(), chunk.size(), 0);
        bytes_sent += chunk_size;
    }
}

void smtp_telnet_client(const std::string &smtp_server, int port) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Convert server address from text to binary form
    if (inet_pton(AF_INET, smtp_server.c_str(), &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address / Address not supported" << std::endl;
        return;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return;
    }

    // Receive initial server's response
    read(sock, buffer, BUFFER_SIZE);
    std::cout << "Server: " << buffer << std::endl;

    std::string user_command;
    while (true) {
        std::cout << "Enter SMTP command (or type 'QUIT' to exit): ";
        std::getline(std::cin, user_command);
          
          if(user_command.substr(0,15) == "SENDATTACHMENT")
          {
            std::string file_path;
            std::cout << "Enter FILE PATH: ";
            std::getline(std::cin, file_path);

            std::ifstream file(file_path, std::ios::binary);
            if (!file) {
                std::cerr << "Error: Could not open file: " << file_path << std::endl;
                continue;
            }

            std::string file_content((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
            file.close();

            std::string encoded_content = base64_encode(file_content);

            user_command = "SENDATTACHMENT:" + fs::path(file_path).filename().string() + ":\r\n";
            std::cout << "Sending attachment metadata...\n";
            send(sock, user_command.c_str(), user_command.size(), 0);

            // Send the attachment data in chunks
            std::cout << "Sending encoded file data...\n";
            send_data_in_chunks(sock, encoded_content);
            std::cout << "File data sent successfully.\n";
          
            
            continue;
         }

          
               
          
          
          
          
          
          
          if(user_command.substr(0,6) == "SIGN_P")
        {string x;
          cout<<"Enter the User name";
          std::getline(std::cin, x);
          string y;
          cout<<"Enter the Password";
          std::getline(std::cin, y); 
          string z;
          cout<<"Enter the Passkey";
          std::getline(std::cin, z); 
          
          if(validate_user_data(x, y))
          { 
          user_command = "SIGN_P:-" + x + "-"+ y + "-" + z;
          }
        }
       
        else if(user_command.substr(0,4) == "SIGN")
        {string x;
          cout<<"Enter the User name";
          std::getline(std::cin, x);
          string y;
          cout<<"Enter the Password";
          std::getline(std::cin, y); 
          if(validate_user_data(x, y))
          { 
          continue;
          }
         user_command = "SIGN:-" + x + "-"+ y;
          }
        
           if(user_command.substr(0,7) == "REPORT")
        {
          string y;
          cout<<"Enter the whom to report";
          std::getline(std::cin, y); 
         
          user_command = "REPORT:"+ y;
          
          }    
        // Append CRLF to the command
        user_command += "\r\n";

        // Send command to the server
        std::cout << "Client: " << user_command;
        send(sock, user_command.c_str(), user_command.size(), 0);
        

        // If the user sends QUIT, break the loop and close the connection
        if (user_command == "QUIT\r\n") {
            break;
        }

        // Receive the server's response
        memset(buffer, 0, BUFFER_SIZE);
        read(sock, buffer, BUFFER_SIZE);
        std::cout << "Server: " << buffer << std::endl;
    }

    close(sock);
}

int main() {
    std::string smtp_server;
    int port;

    // Get SMTP server address and port from user
    std::cout << "Enter SMTP server address: ";
    std::getline(std::cin, smtp_server);

    std::cout << "Enter SMTP server port (default is 25): ";
    std::cin >> port;
    std::cin.ignore();  // Ignore leftover newline character

    // Run the client
    smtp_telnet_client(smtp_server, port);

    return 0;
}
