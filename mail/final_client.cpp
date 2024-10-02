#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <regex>
#include <string>

using namespace std;
#define BUFFER_SIZE 1024

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
          user_command = "SIGN:-" + x + "-"+ y;
          }
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
