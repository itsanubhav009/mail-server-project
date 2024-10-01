#include <string.h>
#include <cstring>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <strings.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <vector>
#include <arpa/inet.h> 
#include <regex> 
#include <pthread.h>

using namespace std;

#define BUFFER_SIZE 1024

void *ftch(void *);
void *snd(void *);
int client_socket;
int getSize;
pthread_mutex_t lock;

/*
    TCP Client class
*/
class TcpClient {
    private: 
        std::string address;
        string response_data = "";
        int port;
        struct sockaddr_in server;

    public:
        int sock;
        TcpClient();
        bool conn(string, int);
        bool send_data(string data);
        string receive(int);
};

bool validate_user_data(const std::string& password) {
    // Basic validation: password must be at least 6 characters and contain both letters and numbers
    if (password.length() < 6) {
        std::cerr << "Password should be at least 6 characters long." << std::endl;
        return false;
    }
    std::regex letter_number_regex("^(?=.*[a-zA-Z])(?=.*[0-9]).+$");
    if (!std::regex_match(password, letter_number_regex)) {
        std::cerr << "Password should contain both letters and numbers." << std::endl;
        return false;
    }

    return true;
}

/*
    Constructor
*/
TcpClient::TcpClient() {
    sock = -1;
    port = 0;
    address = "";
}

/*
    Connect to a host on a certain port number
*/
bool TcpClient::conn(string address , int port) {
    // create socket if it is not already created
    if(sock == -1) {
        //Create socket
        sock = socket(AF_INET , SOCK_STREAM , 0);
        if (sock == -1) {
            perror("Could not create socket");
            return false;
        }

        cout << "Socket created\n";
    }

    // setup address structure
    if(inet_addr(address.c_str()) == -1) {
        struct hostent *he;
        struct in_addr **addr_list;

        // resolve the hostname, it's not an IP address
        if ( (he = gethostbyname( address.c_str() ) ) == NULL) {
            // gethostbyname failed
            herror("gethostbyname");
            cout << "Failed to resolve hostname\n";
            return false;
        }

        addr_list = (struct in_addr **) he->h_addr_list;
        for(int i = 0; addr_list[i] != NULL; i++) {
            server.sin_addr = *addr_list[i];
            cout << address << " resolved to " << inet_ntoa(*addr_list[i]) << endl;
            break;
        }
    } else {
        server.sin_addr.s_addr = inet_addr(address.c_str());
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    //Connect to remote server
    if( connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0 ) {
        perror("connect failed. Error");
        return false;
    }

    cout << "Connected\n";
    return true;
}

TcpClient c;
int main(int argc, char *argv[]) {
    pthread_t procThread[2];
    string host;
    int port;

    cout << "Enter hostname: ";
    cin >> host;
    cout << "Enter port: ";
    cin >> port;

    // connect to host
    if (!c.conn(host, port)) {
        return 1;
    }

    // Initialize mutex for thread synchronization
    pthread_mutex_init(&lock, NULL);

    // Create threads for sending and receiving messages
    pthread_create(&procThread[0], NULL, ftch, NULL); 
    pthread_create(&procThread[1], NULL, snd, NULL); 

    // Wait for the threads to complete
    for(int idx = 0; idx < 2; idx++) {
        pthread_join(procThread[idx], NULL);
    }

    // Clean up
    pthread_mutex_destroy(&lock);
    return 0;
}

void *snd(void *dummy) {   
    char buffer[BUFFER_SIZE] = {0};
    std::string user_command;

    while (true) {
        std::cout << "Enter SMTP command (or type 'QUIT' to exit): ";
        std::getline(std::cin, user_command);

        if (user_command.substr(0, 4) == "SIGN") {
            string username, password;
            cout << "Enter the Username: ";
            std::getline(std::cin, username);
            cout << "Enter the Password: ";
            std::getline(std::cin, password); 
            if (validate_user_data(password)) {
                user_command = "SIGN:-" + username + "-" + password;
            } else {
                continue;
            }
        } else if (user_command.substr(0, 6) == "REPORT") {
            string recipient;
            cout << "Enter whom to report: ";
            std::getline(std::cin, recipient);
            user_command = "REPORT:-" + recipient;
        }

        // Append CRLF to the command
        user_command += "\r\n";

        // Send command to the server
        std::cout << "Client: " << user_command;
        pthread_mutex_lock(&lock);
        send(c.sock, user_command.c_str(), user_command.size(), 0);
        pthread_mutex_unlock(&lock);

        // If the user sends QUIT, break the loop and close the connection
        if (user_command == "QUIT\r\n") {
            close(c.sock);
            pthread_exit(NULL);
        }

        // Receive the server's response
        memset(buffer, 0, BUFFER_SIZE);
        recv(c.sock, buffer, BUFFER_SIZE, 0);
        std::cout << "Server: " << buffer << std::endl;
    }

    return NULL;
}

void *ftch(void *dummy) {
    char buffer[BUFFER_SIZE];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int size = recv(c.sock, buffer, sizeof(buffer), 0);

        if (size < 0) {
            cout << "\rReceive Failed" << endl; 
            break; 
        } else if (size == 0) {
            cout << "\rConnection closed by the server." << endl;
            close(c.sock);
            pthread_exit(NULL);
        } else {
            std::cout << "\rServer> " << buffer << std::endl;
        }
    }

    close(c.sock);
    pthread_exit(NULL);
}
