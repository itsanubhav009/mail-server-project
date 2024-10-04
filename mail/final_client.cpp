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

std::string base64_encode(const std::string &data)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string encoded_string;
    int val = 0, valb = -6;
    for (unsigned char c : data)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            encoded_string.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        encoded_string.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded_string.size() % 4)
        encoded_string.push_back('=');
    return encoded_string;
}

bool validate_user_data(const std::string &username, const std::string &password)
{
    // Simple regex to validate email format
    const std::regex email_regex(R"((\w+)(\.{1})?(\w*)@(\w+)(\.\w+)+)");

    if (!std::regex_match(username, email_regex))
    {
        std::cerr << "Invalid email format." << std::endl;
        return false;
    }

    if (password.length() < 6)
    {
        std::cerr << "Password should be at least 6 characters long." << std::endl;
        return false;
    }

    return true;
}
void send_data_in_chunks(int sock, const std::string &data)
{
    size_t total_size = data.size();
    size_t bytes_sent = 0;

    while (bytes_sent < total_size)
    {
        size_t chunk_size = std::min(static_cast<size_t>(BUFFER_SIZE), total_size - bytes_sent);
        std::string chunk = data.substr(bytes_sent, chunk_size);
        send(sock, chunk.c_str(), chunk.size(), 0);
        bytes_sent += chunk_size;
    }
}

void smtp_telnet_client(const std::string &smtp_server, int port)
{
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        std::cerr << "Socket creation error" << std::endl;
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Convert server address from text to binary form
    if (inet_pton(AF_INET, smtp_server.c_str(), &serv_addr.sin_addr) <= 0)
    {
        std::cerr << "Invalid address / Address not supported" << std::endl;
        return;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cerr << "Connection failed" << std::endl;
        return;
    }

    // Receive initial server's response
    read(sock, buffer, BUFFER_SIZE);
    std::cout << "Server: " << buffer << std::endl;
    std::string user_command;

    while (true)
    {
        int choice;
        cout << "Press 1 TO SIGNUP" << endl;
        cout << "Press 2 TO LOGIN" << endl;
        cout << "Enter in server after login" << endl;
        cin >> choice;
        if (choice == 1)
        {
            int next_choice;
            cout << "Press 1 TO SIGNUP as a user" << endl;
            cout << "Press 2 TO Singup For a domain" << endl;
            cin >> next_choice;
            if (next_choice == 2)
            {
                string x;
                cout << "Enter the User name with Domain\n";
                std::getline(std::cin, x);
                string y;
                cout << "Enter the Password\n";
                std::getline(std::cin, y);
                string z;
                cout << "Enter the Passkey\n";
                std::getline(std::cin, z);

                if (validate_user_data(x, y))
                {
                    string user_command = "SIGN_P:-" + x + "-" + y + "-" + z;
                    user_command += "\r\n";
                    std::cout << "Client: " << user_command;
                    send(sock, user_command.c_str(), user_command.size(), 0);
                    std::cout << "Server: " << buffer << std::endl;
                }
            }
            else if (next_choice == 1)
            {
                string x;
                cout << "Enter the User name\n";
                std::getline(std::cin, x);
                string y;
                cout << "Enter the Password\n";
                std::getline(std::cin, y);
                if (validate_user_data(x, y))
                {
                    continue;
                }
                user_command = "SIGN:-" + x + "-" + y;
                user_command += "\r\n";
                std::cout << "Client: " << user_command;
                send(sock, user_command.c_str(), user_command.size(), 0);
                std::cout << "Server: " << buffer << std::endl;
            }
        }

        if (choice == 2)
        {
            string x;
            cout << "Enter the User name\n";
            std::getline(std::cin, x);
            user_command = "USER:" + x;
            user_command += "\r\n";
            std::cout << "Client: " << user_command;
            send(sock, user_command.c_str(), user_command.size(), 0);
            std::cout << "Server: " << buffer << std::endl;
            if (buffer == "+OK User OK, send password")
            {
                string y;
                cout << "Enter the Password\n";
                std::getline(std::cin, y);
                user_command = "PASS:" + x;
                user_command += "\r\n";
                std::cout << "Client: " << user_command;
                send(sock, user_command.c_str(), user_command.size(), 0);
                std::cout << "Server: " << buffer << std::endl;
            }
            else
            {
                continue;
            }
            if (buffer == "+OK Password accepted")
            {
                break;
            }
            
        }
    }

    while (true)
    {
        std::cout << "Enter SMTP command (or type 'QUIT' to exit): ";
        std::getline(std::cin, user_command);

        std::cout << "Press 1 to send mail\n";
        std::cout << "Press 2 to List mail\n";
        std::cout << "Press 3 to Delete mail\n";
        std::cout << "Press 4 to Reset mail\n";
        std::cout << "Press 5 to Register a domain\n";
        std::cout << "Press 6 to Report\n";
        std::cout << "Press 7 to Get Acess to send mail to a domain\n";
        std::cout << "Press 8 to Give acess\n";
        std::cout << "Press 9 to NOOP\n";
        std::cout << "Press 10 to QUIT\n";
        std::cout << "Press 11 to Show all Stat\n";
        std::cout << "Press 12 to Show Last mail\n";
        std::cout << "Press 13 to Show current login information\n";
        std::cout << "Press 14 to change Current Password\n";
        std::cout << "Press 15 to Remove Access\n";
        std::cout << "Press 16 to Change Passkey\n";
        std::cout << "Press 17 to Show First mail\n";
        std::cout << "Press 18 to Download a File\n";

        int choice;
        cin >> choice;
        if (choice == 1)
        {
            std::cout << "Enter From Which mail to send\n";
            string y;
            std::getline(std::cin, y);
            user_command = "MAIL_FROM:" + y;
            user_command += "\r\n";
            std::cout << "Client: " << user_command;
            send(sock, user_command.c_str(), user_command.size(), 0);
            memset(buffer, 0, BUFFER_SIZE);
            read(sock, buffer, BUFFER_SIZE);
            std::cout << "Server: " << buffer << std::endl;
            if (buffer == "+OK User is valid")
            {
                int p;
                p = 0;

                do
                {
                    cout << "Enter THE mail to send\n";
                    string x;
                    std::getline(std::cin, x);
                    user_command = "RCPT_TO" + x;
                    user_command += "\r\n";
                    std::cout << "Client: " << user_command;
                    send(sock, user_command.c_str(), user_command.size(), 0);
                    std::cout << "Server: " << buffer << std::endl;
                    if (buffer == "-ERR Invalid mail")
                    {
                        cout << "Press 1 if you  want to try once more to Enter the mail\n";
                        cin >> p;
                    }
                } while (p == 1);

                if (buffer == "+OK Recipient is valid")
                {
                    cout << "Press 1 if You want to send the Data\n";
                    cout << "Press 2 if You want to send the Attachment\n";
                    cout << "Press 3 if You want Quit the process\n";
                    int ch;
                    cin >> ch;
                    if (ch == 1)
                    {
                        user_command = "DATA:";
                        user_command += "\r\n";
                        std::cout << "Client: " << user_command;
                        send(sock, user_command.c_str(), user_command.size(), 0);
                        memset(buffer, 0, BUFFER_SIZE);
                        read(sock, buffer, BUFFER_SIZE);
                        std::cout << "Server: " << buffer << std::endl;
                    }
                    if (buffer == "354 Start mail input; end with <CRLF>.<CRLF>")
                    {

                        do
                        {
                            cout << "Enter the DATA to send\n";
                            cout << "Press . to sent the data\n";
                            string z;
                            std::getline(std::cin, z);
                            if (z == ".")
                            {
                                user_command = z;
                                user_command += "\r\n";
                                std::cout << "Client: " << user_command;
                                send(sock, user_command.c_str(), user_command.size(), 0);
                                memset(buffer, 0, BUFFER_SIZE);
                                read(sock, buffer, BUFFER_SIZE);
                                std::cout << "Server: " << buffer << std::endl;
                            }
                            else
                            {
                                user_command = z;
                                user_command += "\r\n";
                                std::cout << "Client: " << user_command;
                                send(sock, user_command.c_str(), user_command.size(), 0);
                                memset(buffer, 0, BUFFER_SIZE);
                                read(sock, buffer, BUFFER_SIZE);
                                std::cout << "Server: " << buffer << std::endl;
                            }
                        } while (buffer == "+OK 250 ok");
                    }
                    else
                    {
                        cout << "Some Error Occured\n";
                        continue;
                    }
                    if (ch == 2)
                    {
                        std::string file_path;
                        std::cout << "Enter FILE PATH with name: ";
                        std::getline(std::cin, file_path);

                        std::ifstream file(file_path, std::ios::binary);
                        if (!file)
                        {
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
                        cout << "Press 1 if you want to complete the process else your file will not be sent\n";
                        int t;
                        cin >> t;
                        if (t == 1)
                        {
                            user_command = "EOF:";
                            user_command += "\r\n";
                            std::cout << "Client: " << user_command;
                            send(sock, user_command.c_str(), user_command.size(), 0);
                            memset(buffer, 0, BUFFER_SIZE);
                            read(sock, buffer, BUFFER_SIZE);
                            std::cout << "Server: " << buffer << std::endl;
                        }
                    }
                }
            }
        }
        if (choice == 2)
        {
            user_command = "LIST:";
            user_command += "\r\n";
            std::cout << "Client: " << user_command;
            send(sock, user_command.c_str(), user_command.size(), 0);
            memset(buffer, 0, BUFFER_SIZE);
            read(sock, buffer, BUFFER_SIZE);
            std::cout << "Server: " << buffer << std::endl;
        }
        if (choice == 3)
        {
            user_command = "DELE";
            user_command += "\r\n";
            std::cout << "Client: " << user_command;
            send(sock, user_command.c_str(), user_command.size(), 0);
            memset(buffer, 0, BUFFER_SIZE);
            read(sock, buffer, BUFFER_SIZE);
            std::cout << "Server: " << buffer << std::endl;
        }
        if (choice == 4)
        {
            user_command = "RSET";
            user_command += "\r\n";
            std::cout << "Client: " << user_command;
            send(sock, user_command.c_str(), user_command.size(), 0);
            memset(buffer, 0, BUFFER_SIZE);
            read(sock, buffer, BUFFER_SIZE);
            std::cout << "Server: " << buffer << std::endl;
        }
        if (choice == 5)
        {
            int c;
            do
            {
                c = 0;
                cout << "Enter the Domain Name to Register\n";
                string x;
                std::getline(std::cin, x);
                user_command = "REGISTER:" + x;
                user_command += "\r\n";
                std::cout << "Client: " << user_command;
                send(sock, user_command.c_str(), user_command.size(), 0);
                memset(buffer, 0, BUFFER_SIZE);
                read(sock, buffer, BUFFER_SIZE);
                std::cout << "Server: " << buffer << std::endl;
                if (buffer == "-ERR Domain already exists" || buffer == "-ERR Invalid command")
                {
                    cout << "Press 1 to Try again OR Press any key to Quit\n";
                    cin >> c;
                }

            } while (c == 1);
        }
        if (choice == 6)
        {
            string x;
            cout << "Press Email to Report\n";
            getline(cin, x);
            user_command = "REPORT:" + x;
            user_command += "\r\n";
            std::cout << "Client: " << user_command;
            send(sock, user_command.c_str(), user_command.size(), 0);
            memset(buffer, 0, BUFFER_SIZE);
            read(sock, buffer, BUFFER_SIZE);
            std::cout << "Server: " << buffer << std::endl;
        }
        if (choice == 7)
        {
            cout << "Enter the Domain to Which you want to get acess for sending mail to that account\n";
            string x;
            std::getline(std::cin, x);
            string y;
            cout << "Enter the Passkey of that domain\n";
            std::getline(std::cin, y);

            user_command = "GETACCESS:" + x + ":" + y;
            user_command += "\r\n";
            std::cout << "Client: " << user_command;
            send(sock, user_command.c_str(), user_command.size(), 0);
            memset(buffer, 0, BUFFER_SIZE);
            read(sock, buffer, BUFFER_SIZE);
            std::cout << "Server: " << buffer << std::endl;
        }
        if (choice == 8)
        {

            cout << "Press 1 to give acess to a domain\n";
            cout << "Press 2 to give acess to a email\n";

            int ch;
            cin >> ch;

            if (ch == 1)
            {
                cout << "Enter the Domain to Which you want to give acess\n";
                string x;
                std::getline(std::cin, x);
                string y;
                cout << "Enter the domain from Which you are giving acess\n";
                std::getline(std::cin, y);

                user_command = "ADDDOMAINACCESS:" + x + ":" + y;
                user_command += "\r\n";
                std::cout << "Client: " << user_command;
                send(sock, user_command.c_str(), user_command.size(), 0);
                memset(buffer, 0, BUFFER_SIZE);
                read(sock, buffer, BUFFER_SIZE);
                std::cout << "Server: " << buffer << std::endl;
            }
            if (ch == 2)
            {
                cout << "Enter the Email to Which you want to give acess\n";
                string x;
                std::getline(std::cin, x);
                string y;
                cout << "Enter the domain from Which you are giving acess\n";
                std::getline(std::cin, y);
                user_command = "ADDE:" + y + ":" + x;
                user_command += "\r\n";
                std::cout << "Client: " << user_command;
                send(sock, user_command.c_str(), user_command.size(), 0);
                memset(buffer, 0, BUFFER_SIZE);
                read(sock, buffer, BUFFER_SIZE);
                std::cout << "Server: " << buffer << std::endl;
            }

            if (choice == 9)
            {
                user_command = "NOOP:";
                user_command += "\r\n";
                std::cout << "Client: " << user_command;
                send(sock, user_command.c_str(), user_command.size(), 0);
                memset(buffer, 0, BUFFER_SIZE);
                read(sock, buffer, BUFFER_SIZE);
                std::cout << "Server: " << buffer << std::endl;
            }
            if (choice == 10)
            {
                user_command = "QUIT:";
                user_command += "\r\n";
                std::cout << "Client: " << user_command;
                send(sock, user_command.c_str(), user_command.size(), 0);
                memset(buffer, 0, BUFFER_SIZE);
                read(sock, buffer, BUFFER_SIZE);
                std::cout << "Server: " << buffer << std::endl;
            }
            if (choice == 11)
            {
                user_command = "STAT:";
                user_command += "\r\n";
                std::cout << "Client: " << user_command;
                send(sock, user_command.c_str(), user_command.size(), 0);
                memset(buffer, 0, BUFFER_SIZE);
                read(sock, buffer, BUFFER_SIZE);
                std::cout << "Server: " << buffer << std::endl;
            }
            if (choice == 12)
            {
                user_command = "LAST";
                user_command += "\r\n";
                std::cout << "Client: " << user_command;
                send(sock, user_command.c_str(), user_command.size(), 0);
                memset(buffer, 0, BUFFER_SIZE);
                read(sock, buffer, BUFFER_SIZE);
                std::cout << "Server: " << buffer << std::endl;
            }
            if (choice == 13)
            {
                user_command = "RETR:";
            }
            if (choice == 14)
            {
                user_command = "CHANGEPASS";
            }
            if (choice == 15)
            {

                cout << "Press 1 to Remove acess from a email\n";
                cout << "Press 2 to Remove acess from a domain\n";
                int ch;
                cin >> ch;
                if (ch == 1)
                {
                    cout << "Enter the Email to Whom you want to remove acess\n";
                    string x;
                    std::getline(std::cin, x);
                    string y;
                    cout << "Enter the domain from Which you want to remove acess\n";
                    std::getline(std::cin, y);
                    user_command = "REMOVEE:" + y + ":" + x;
                    user_command += "\r\n";
                    std::cout << "Client: " << user_command;
                    send(sock, user_command.c_str(), user_command.size(), 0);
                    memset(buffer, 0, BUFFER_SIZE);
                    read(sock, buffer, BUFFER_SIZE);
                    std::cout << "Server: " << buffer << std::endl;
                }
                if (ch == 2)
                {
                    cout << "Enter the Domain to Which you want to remove acess\n";
                    string x;
                    std::getline(std::cin, x);
                    string y;
                    cout << "Enter the domain from Which you are removing acess\n";
                    std::getline(std::cin, y);
                    user_command = "REMOVEDOMAINACCESS:" + x + ":" + y;
                    user_command += "\r\n";
                    std::cout << "Client: " << user_command;
                    send(sock, user_command.c_str(), user_command.size(), 0);
                    memset(buffer, 0, BUFFER_SIZE);
                    read(sock, buffer, BUFFER_SIZE);
                    std::cout << "Server: " << buffer << std::endl;
                }
            }
        }
        if (choice == 16)
        {
            cout << "Enter the domain whoose pass key you want to change\n";
            string x;
            std::getline(std::cin, x);

            user_command = "CHANGEPASSKEY:" + x;
            user_command += "\r\n";
            std::cout << "Client: " << user_command;
            send(sock, user_command.c_str(), user_command.size(), 0);
            memset(buffer, 0, BUFFER_SIZE);
            read(sock, buffer, BUFFER_SIZE);
            std::cout << "Server: " << buffer << std::endl;
        }
        if (choice == 17)
        {
            user_command = "TOP:";
            user_command += "\r\n";
            std::cout << "Client: " << user_command;
            send(sock, user_command.c_str(), user_command.size(), 0);
            memset(buffer, 0, BUFFER_SIZE);
            read(sock, buffer, BUFFER_SIZE);
            std::cout << "Server: " << buffer << std::endl;
        }
        if (choice == 18)
        {
            cout << "Enter the file name to download\n";
            string x;

            user_command = "FILED" + x;
            user_command += "\r\n";
            std::cout << "Client: " << user_command;
            send(sock, user_command.c_str(), user_command.size(), 0);
            memset(buffer, 0, BUFFER_SIZE);
            read(sock, buffer, BUFFER_SIZE);
            std::cout << "Server: " << buffer << std::endl;
        }

      

        // If the user sends QUIT, break the loop and close the connection
        if (user_command == "QUIT\r\n")
        {
            break;
        }

   
    }

    close(sock);
}

int main()
{
    std::string smtp_server;
    int port;

    // Get SMTP server address and port from user
    std::cout << "Enter SMTP server address: ";
    std::getline(std::cin, smtp_server);

    std::cout << "Enter SMTP server port (default is 25): ";
    std::cin >> port;
    std::cin.ignore(); // Ignore leftover newline character

    // Run the client
    smtp_telnet_client(smtp_server, port);

    return 0;
}
