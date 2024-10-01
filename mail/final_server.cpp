
#include<cstring>



#include <sqlite3.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <cstring>
#include <sstream>
#include <algorithm> 
#include <cctype>
#include <locale>
#include <string>
#include <algorithm> 
#include <cctype>
#include "globals.h"
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <pthread.h>
#include <fstream>
using namespace std;

int thread_count = 0; // counts number of logged in users
vector<mailAccounts>listUser; //stores list of users email
sem_t mutex;
typedef int (*execFunction)(pop3User &user);



sqlite3 *db;

struct mail {
    int serialNo;
    int fileSize;
    string sender;
    string date;
    bool deleted;
    string content;
};

struct mailAccounts {
    int count;
    int lastmsg;
    bool lock;
    string email;
};

extern vector<mailAccounts> listUser;
class pop3User {
public:
    bool session;
    bool mailLock;
    bool checked;
     vector<mail> emails;
    bool expecting_data_ = false;
    unsigned int index;
    unsigned int m_nLastMsg;
    unsigned int clientSocket;
    unsigned int state;
    unsigned int mailCount;
    unsigned int TotalmailSize;
    string userEmail;
    string clientMessage;
    string AuthCode;
    string recipient;

    // Constructor
    pop3User(int &client_soc);

    // Virtual destructor (to be explicitly defined in the cpp)
    virtual ~pop3User(void);

    // Function to send responses
    int SendResponse(int nResponseType, const char *msg);  // Use const char* for immutability
    int SendResponse(int nResponseType);
    int SendResponse(const char *msg);  // Same change here

    // Getter for client socket, declared const since it doesn't modify class members
    int get_clientSocket() ;
   
};


// Function to trim leading and trailing whitespaces
std::string trim(const std::string s) {
    // Find the first character that is not a space from the start
    auto start = std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    });

    // Find the last character that is not a space from the end
    auto end = std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base();
    

    // Return the trimmed string. If no spaces were found, return an empty string
    return (start < end ? std::string(start, end) : std::string());
}


bool connectToDatabase() {
    const char DebugPrefix[] = "DEBUG [connectToDatabase]: ";
    const char *path_to_db_file = "mailserver.db"; // Replace with your actual DB path

    // Debug: Log the database file path
    std::cout << DebugPrefix << "Database file path: " << path_to_db_file << std::endl;

    // Attempt to open the database connection
    int rc = sqlite3_open(path_to_db_file, &db);
    if (rc) {
        cerr << DebugPrefix << "Can't open database: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    
   
    if (rc != SQLITE_OK) {
        cerr << DebugPrefix << "SQL error while ensuring users table: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }

    std::cout << DebugPrefix << "Opened database successfully." << std::endl;
    return true;
}

void closeDatabase() {
    sqlite3_close(db);
}

pop3User::pop3User(int &client_soc)
{
    clientSocket = client_soc;
    state = POP3_STATE_AUTHORIZATION;
}

int pop3User::get_clientSocket()
{
    return clientSocket;
}

pop3User::~pop3User(void)
{
    emails.clear();
}

int pop3User::SendResponse(int nResponseType, const char *msg)
{   
    char clientMessage[client_message_SIZE];
    if(nResponseType == POP3_DEFAULT_AFFERMATIVE_RESPONSE)
    {
        if(strlen(msg))
            sprintf(clientMessage, "+OK %s\r\n", msg);
        else
            sprintf(clientMessage, "+OK Action performed\r\n");
    }
    else if(nResponseType == POP3_DEFAULT_NEGATIVE_RESPONSE)
    {
        if(strlen(msg))
            sprintf(clientMessage, "-ERR %s\r\n", msg);
        else
            sprintf(clientMessage, "-ERR An error occurred\r\n");
    }
    
    int len = static_cast<int>(strlen(clientMessage));
    std::cout << "Sending: " << clientMessage;
    write(clientSocket, clientMessage, len);
    return nResponseType;
}

string skipWhitespace(string message)
{
    size_t start = message.find_first_not_of(" ");
    size_t end = message.find_last_not_of(" ");
    return (start == string::npos || end == string::npos) ? "" : message.substr(start, end - start + 1);
}

bool lockMail(pop3User &user) {
    string query = "UPDATE users SET locked = 1 WHERE email = ? AND locked = 0;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        cerr << "SQL error: " << sqlite3_errmsg(db) << endl;
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, user.userEmail.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE);
}

void unlockMail(pop3User &user) {
    string query = "UPDATE users SET locked = 0 WHERE email = ?;";
    sqlite3_stmt *stmt;
    
    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, user.userEmail.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void getMail(pop3User &user) {
    if (!user.checked) {
        string query = "SELECT id, sender, subject, size, date_sent FROM emails WHERE user_id = (SELECT id FROM users WHERE email = ?) AND deleted = 0;";
        sqlite3_stmt *stmt;

        sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, user.userEmail.c_str(), -1, SQLITE_STATIC);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int id = sqlite3_column_int(stmt, 0);
            string sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            string subject = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            int size = sqlite3_column_int(stmt, 3);
            string date = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            user.emails.push_back({id, size, subject, sender, false});
        }
        
        user.mailCount = sqlite3_changes(db);
        sqlite3_finalize(stmt);
        user.checked = true;
    }
}

int ProcessRPOP(pop3User &user) {
    string query = "SELECT email FROM users WHERE password = ?;";
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, user.AuthCode.c_str(), -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user.userEmail = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, "");
    }

    sqlite3_finalize(stmt);
    return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, "Invalid Auth Code");
}

int ProcessPASS(pop3User &user)
{
    const char InvalidAuth[] = "Invalid password";

    // Check if user has provided an email first
    if (user.userEmail.empty()) {
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, "USER command required first");
    }

    // Query the database to validate the password
    string query = "SELECT password FROM user WHERE email = ? AND password = ?;";
    sqlite3_stmt *stmt;
    user.clientMessage =  user.clientMessage.substr(5);
    std::cout<<"Email:"<<user.userEmail<<endl<<"password:"<<user.clientMessage<<endl;
    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, user.userEmail.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user.clientMessage.c_str(), -1, SQLITE_STATIC);  // Assuming password is stored in `AuthCode`
    std::cout<<SQLITE_ROW<<endl;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // Password is correct, transition to TRANSACTION state
        user.state = POP3_STATE_TRANSACTION;
        sqlite3_finalize(stmt);
        return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, "Password accepted");
    }

    sqlite3_finalize(stmt);
    return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, InvalidAuth);
}


int ProcessUSER(pop3User &user)
{
    const char InvalidAuth[] = "Mailbox does not exist";
    const char DebugPrefix[] = "DEBUG [ProcessUSER]: ";
    const char QueryError[] = "SQL query error";

    // Step 1: Connect to the database
    connectToDatabase();  
    std::cout << DebugPrefix << "Connecting to database..." << endl;

    // Check if the database connection is open
    if (!db) {
        cerr << DebugPrefix << "Database connection is not open." << endl;
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, "Database not connected");
    } else {
        std::cout << DebugPrefix << "Database connection opened successfully." << endl;
    }

    // Step 2: Prepare SQL query
    string query = "SELECT email FROM user WHERE email = ?;";
    sqlite3_stmt *stmt;

    std::cout << DebugPrefix << "Preparing SQL query: " << query << endl;
    int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        cerr << DebugPrefix << QueryError << ": Failed to prepare statement. Error: " << sqlite3_errmsg(db) << " (" << rc << ")" << endl;
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, InvalidAuth);
    } else {
        std::cout << DebugPrefix << "SQL statement prepared successfully." << endl;
    }
    
      user.clientMessage = user.clientMessage.substr(5);
    // Step 3: Bind email to the prepared statement
    std::cout << DebugPrefix << "Binding user-provided email to query: " << user.clientMessage << endl;
    rc = sqlite3_bind_text(stmt, 1, user.clientMessage.c_str(), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        cerr << DebugPrefix << "Failed to bind email: " << user.AuthCode << ". Error: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, InvalidAuth);
    } else {
        std::cout << DebugPrefix << "Bound email to query successfully." << endl;
    }

    // Step 4: Execute the query and check for results
    std::cout << DebugPrefix << "Executing the query..." << endl;
    bool emailFound = false;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        // Email found, print both the provided and retrieved email for validation
        const char* retrievedEmail = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::cout << DebugPrefix << "Email found in database: " << retrievedEmail << endl;
        std::cout << DebugPrefix << "Comparing database email with user-provided email: " << user.AuthCode << endl;
          std::cout<<retrievedEmail<<endl;
        // Compare the retrieved email with the one the user provided
        if (user.clientMessage == retrievedEmail) {
            std::cout << DebugPrefix << "User email matches with database." << endl;
            user.userEmail = user.clientMessage;
            emailFound = true;
        } else {
            std::cout << DebugPrefix << "User email does not match with database email." << endl;
        }
    }

    // Step 5: Check if no matching emails were found
    if (!emailFound) {
        std::cout << DebugPrefix << "No matching emails found for the given query." << endl;
        sqlite3_finalize(stmt);
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, InvalidAuth);
    }

    // Step 6: Finalize the statement
    sqlite3_finalize(stmt);
    std::cout << DebugPrefix << "SQL statement finalized." << endl;

    return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, "User OK, send password");
}



int ProcessQUIT(pop3User &user) {
    const char quit[] = "Goodbye, exiting user Email";
    
    if (user.state == POP3_STATE_TRANSACTION) {
        user.state = POP3_STATE_UPDATE;

        for (auto &email : user.emails) {
            if (email.deleted) {
                // Instead of removing the file, mark the email as deleted in the database
                string query = "UPDATE emails SET deleted = 1 WHERE id = ?;";
                sqlite3_stmt *stmt;

                sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
                sqlite3_bind_int(stmt, 1, email.serialNo);  // Assuming serialNo matches the email ID
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
        unlockMail(user);
    }
    user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, quit);
    return -1;
}



int ProcessSTAT(pop3User &user) {
    string query = "SELECT COUNT(*), SUM(size) FROM emails WHERE user_id = (SELECT id FROM users WHERE email = ?) AND deleted = 0;";
    sqlite3_stmt *stmt;
    int totalMessages = 0, totalSize = 0;

    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, user.userEmail.c_str(), -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        totalMessages = sqlite3_column_int(stmt, 0);
        totalSize = sqlite3_column_int(stmt, 1);
    }
    sqlite3_finalize(stmt);

    string response = to_string(totalMessages) + " messages, " + to_string(totalSize) + " bytes";
    return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, response.c_str());
}

int ProcessLIST(pop3User &user)
{
    const char error[] = "Invalid Command";

    if (user.state != POP3_STATE_TRANSACTION) {
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, "USER and PASS commands required first");
    }
   std::cout<<user.clientMessage<<endl;
    string trimmedMessage = user.clientMessage.substr(0,4);
     std::cout<<"Trimmed MESSAGE"<<endl;
    if (trimmedMessage == "LIST") {
        string query = "SELECT id, sender, data FROM emails WHERE recipient = ?;";
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, "Database error");
        }

        sqlite3_bind_text(stmt, 1, user.userEmail.c_str(), -1, SQLITE_STATIC);

        int mailCount = 0;
        string message = "+OK Mail list follows:";
        user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, message.c_str());

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int emailId = sqlite3_column_int(stmt, 0);
            const char *sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            const char *emailData = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

            string resp = to_string(++mailCount) + " " + string(sender) + " " + to_string(strlen(emailData)) + " bytes";
            user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp.c_str());
        }

        sqlite3_finalize(stmt);
        user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, ".");

        return POP3_DEFAULT_AFFERMATIVE_RESPONSE;
    }
    else {
        try {
            int messageNumber = stoi(trim(user.clientMessage.substr(5)));

            string query = "SELECT id, sender, data FROM emails WHERE recipient = ? LIMIT 1 OFFSET ?;";
            sqlite3_stmt *stmt;

            if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
                return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, "Database error");
            }

            sqlite3_bind_text(stmt, 1, user.userEmail.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 2, messageNumber - 1);

            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *sender = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                const char *emailData = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

                string resp = to_string(messageNumber) + " " + string(sender) + " " + to_string(strlen(emailData)) + " bytes";
                sqlite3_finalize(stmt);
                return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp.c_str());
            }

            sqlite3_finalize(stmt);
            return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, "No such message");
        }
        catch (...) {
            return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, error);
        }
    }

    return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, error);
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}


int SendMessage(pop3User &user, int mID, int option) {
    if (mID < 0 || mID >= user.emails.size()) {
        string errorMsg = "-ERR Invalid message ID\r\n";
        send(user.clientSocket, errorMsg.c_str(), errorMsg.length(), 0);
        return -1;
    }

    const mail &message = user.emails[mID];

    // Fetch the full email content from the database
    if (option == 0) { // Send full message
        string query = "SELECT content FROM emails WHERE id = ?;";
        sqlite3_stmt *stmt;

        sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, message.serialNo);  // Assuming serialNo matches the email ID

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            string content = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            string response = "+OK " + to_string(mID + 1) + " " + to_string(message.fileSize) + "\r\n" +
                              content + "\r\n.\r\n";
            send(user.clientSocket, response.c_str(), response.length(), 0);
        }
        sqlite3_finalize(stmt);
    }
    return 0; // Success
}



int ProcessRETR(pop3User &user)
{
    printf("Processing RETR Command ...\n");
    char invalid[] = "Invalid Command";
    
    // Split the client message into command and parameter
    std::string command, messageID;
    std::istringstream iss(user.clientMessage);
    iss >> command >> messageID;  // Extract the "RETR" and the "1"

    // Check if the command is correct and there's a valid message ID
    if (command != "RETR" || messageID.empty() || !std::isdigit(messageID[0])) 
    {
        printf("Invalid message ID: %s\n", user.clientMessage.c_str());
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);
    }

    // Convert message ID to integer
    int mID = -1;
    try 
    {
        mID = stoi(messageID);
    } 
    catch (const std::invalid_argument &e) 
    {
        printf("Conversion error: invalid argument for stoi\n");
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);
    } 
    catch (const std::out_of_range &e) 
    {
        printf("Conversion error: out of range for stoi\n");
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);
    }

    // Ensure the state is correct
    if (user.state != POP3_STATE_TRANSACTION)
    {
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);
    }

    // Check if the message ID is valid and if the email exists
    if (mID > user.mailCount || mID < 1 || user.emails[mID - 1].deleted) 
    {
        char invalid1[] = "Message does not exist";
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid1);
    }

    // Check if the email has a valid size
    if (user.emails[mID - 1].fileSize <= 0)
    {
        printf("Warning: Email size is zero or negative\n");
    }

    // Prepare and send response with email size
    char resp[50];
    sprintf(resp, " %d bytes\r\n", user.emails[mID - 1].fileSize);
    user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp);

    // Make sure to check email content length before sending to avoid bad_alloc
    if (user.emails[mID - 1].content.size() > 0)
    {
        SendMessage(user, mID, 0);
    }
    else
    {
        printf("Warning: No email content to send\n");
    }

    return POP3_DEFAULT_AFFERMATIVE_RESPONSE;
}


int ProcessDELE(pop3User &user) {
    int msg_id = stoi(user.clientMessage);
    string query = "UPDATE emails SET deleted = 1 WHERE id = ? AND user_id = (SELECT id FROM users WHERE email = ?);";
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, msg_id);
    sqlite3_bind_text(stmt, 2, user.userEmail.c_str(), -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, "Delete failed");
    }

    user.mailCount--;
    sqlite3_finalize(stmt);
    return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, "Message deleted");
}



int ProcessLAST(pop3User &user)
{
	char empty[] = "";
	if(user.state!=POP3_STATE_TRANSACTION)
	{
		return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, empty);
	}
	printf("Processing LAST accessed message...\n");
	char resp[25];
	sprintf(resp, "%d",user.m_nLastMsg);
	return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp);
}



int ProcessRSET(pop3User &user)
{
	char empty[] = "";
	printf("Resetting mailBox...\n");
	if(user.state!=POP3_STATE_TRANSACTION)
	{
		return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, empty);
	}
	int i,filesize = 0;
	for(i=0; i < user.emails.size(); i++)
	{
		user.emails[i].deleted = false;
		filesize += user.emails[i].fileSize;
	}
	user.mailCount = i;
	user.TotalmailSize = filesize;
	string message = "mail drop has " + to_string(user.mailCount) 
	+ " messages, "+to_string(user.TotalmailSize) +" bytes";
	char* resp = new char[message.size() +1];
	strcpy(resp, message.c_str());
	return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp);
}


int ProcessTOP(pop3User &user)
{
	int mID = stoi(user.clientMessage.substr(0, user.clientMessage.find(' ')));
	int topC= stoi(user.clientMessage.substr(user.clientMessage.find_last_of(' ') + 1));
	printf("Processing TOP ...\n");
	char invalid[] = "Invalid Command";
	if(user.state != POP3_STATE_TRANSACTION)
	{
		return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);
	}
	if(mID >= user.TotalmailSize || user.emails[mID].deleted == true) 
	{
		char invalid1[] = "Message does not exist";
		return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid1);
	}

	if(user.m_nLastMsg < (unsigned int)mID) 
		user.m_nLastMsg = mID;

	char resp[25];
	sprintf(resp," %d bytes\r\n",user.emails[mID-1].fileSize);
	user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp);
	
	return POP3_DEFAULT_NEGATIVE_RESPONSE;
}

//List of functions used to process the pop3 commands from the client
std::string signup( std::string& username,  std::string& password) {
    // Validate the user data
   

    // Hash the password
    std::string hashed_password = password;

     int rc = sqlite3_open("mailserver.db", &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        if (db) sqlite3_close(db);
        return "Database is not opened";
    }

    // Prepare SQL statement for inserting user
    const char* sql = "INSERT INTO user (email, password) VALUES (?, ?);";
    sqlite3_stmt* stmt;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return "Database error.";
    }

    // Bind parameters
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashed_password.c_str(), -1, SQLITE_STATIC);

    // Execute the statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Error executing statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return "Signup failed. Username may already exist.";
    }

    // Clean up
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return "Signup successful!";
}
std::string trim1(const std::string& str) {
    std::string result = str;
    
    // Remove leading spaces
    result.erase(result.begin(), std::find_if(result.begin(), result.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    
    // Remove trailing spaces
    result.erase(std::find_if(result.rbegin(), result.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), result.end());

    return result;
}
void store_email_in_db_v2(const std::string& sender, const std::string& recipient, const std::string& data) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    int rc;

    // Open the database connection
    rc = sqlite3_open("mailserver.db", &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);  // Always close the database if there's an error
        return;
    }
    std::cout << "Database opened successfully." << std::endl;

    // Prepare the SQL statement
    std::string sql = "INSERT INTO emails (sender, recipient, data) VALUES (?, ?, ?)";
    rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare SQL statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);  // Close database on error
        return;
    }
    std::cout << "SQL statement prepared successfully." << std::endl;

    // Bind the sender, recipient, and data to the SQL statement
    rc = sqlite3_bind_text(stmt, 1, sender.c_str(), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to bind sender: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    rc = sqlite3_bind_text(stmt, 2, recipient.c_str(), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to bind recipient: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    rc = sqlite3_bind_text(stmt, 3, data.c_str(), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to bind data: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }
    std::cout << "Binding of parameters successful." << std::endl;

    // Execute the SQL statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute SQL statement: " << sqlite3_errmsg(db) << std::endl;
    } else {
        std::cout << "Email successfully inserted into the database." << std::endl;
    }

    // Finalize the statement and close the database
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}


int ProcessMAIL_FROM(pop3User &user)
{
   char invalid[] = "Invalid mail";
   if ( user.clientMessage.substr(0, 10) == "MAIL_FROM") {
        string sender =  user.clientMessage.substr(10);
        sender.erase(remove(sender.begin(), sender.end(), '\r'), sender.end());
        if (user.userEmail != sender) {
            return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);

        }
        string resp = "User is valid";
        return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp.c_str());
    }

    return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);

}
bool recipient_exists(const std::string& recipient) {
    sqlite3* db;
    sqlite3_open("mailserver.db", &db);

    std::string sql = "SELECT COUNT(*) FROM user WHERE email = ?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, recipient.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    bool exists = (sqlite3_column_int(stmt, 0) > 0);

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return exists;
}


int ProcessRCPT_TO(pop3User &user)
{
   char invalid[] = "Invalid mail";
 if (user.clientMessage.substr(0, 7) == "RCPT_TO") {
        user.recipient = user.clientMessage.substr(7);
        user.recipient.erase(remove(user.recipient.begin(), user.recipient.end(), '\r'), user.recipient.end());
        if (!recipient_exists(user.recipient)) {
             return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);
        }
        string resp = "Recipient is valid";
        return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp.c_str());
    }
    return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);
}


int ProcessDATA(pop3User &user)
{ char invalid[] = "Invalid command";
if (user.clientMessage.substr(0,4) == "DATA") {
        user.expecting_data_ = true;
        string resp =  "354 Start mail input; end with <CRLF>.<CRLF>";
       return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp.c_str());
    }
     return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);

}
int reportEmail(std::string user_email, std::string reported_email) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    
    const char *db_name = "mailserver.db";

    // Open SQLite database
    std::cout << "Opening database: " << db_name << std::endl;
    rc = sqlite3_open(db_name, &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }
    std::cout << "Database opened successfully!" << std::endl;

  user_email = trim1(user_email);
   reported_email = trim1(reported_email);
    
  // Step 1: Check if the reported_email exists in the email table for the user_email
std::cout << "Preparing SQL query: SELECT sender FROM emails WHERE recipient = ? AND sender = ?" << std::endl;
std::string query = "SELECT sender FROM emails WHERE recipient = ? AND sender = ?";

cout<<user_email<<reported_email;
rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
if (rc != SQLITE_OK) {
    std::cerr << "SQL error (prepare failed): " << sqlite3_errmsg(db) << std::endl;
    sqlite3_close(db);
    return rc;
} else {
    std::cout << "SQL query prepared successfully." << std::endl;
}

// Log string lengths to detect any trailing spaces or invisible characters
std::cout << "Length of user_email (recipient): " << user_email.length() << std::endl;
std::cout << "Length of reported_email (sender): " << reported_email.length() << std::endl;

// Bind user_email to the first parameter (recipient)
std::cout << "Binding user_email (recipient: '" << user_email << "') to the first parameter." << std::endl;
rc = sqlite3_bind_text(stmt, 1, user_email.c_str(), -1, SQLITE_STATIC);
if (rc != SQLITE_OK) {
    std::cerr << "SQL error (bind failed for recipient): " << sqlite3_errmsg(db) << std::endl;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
} else {
    std::cout << "Binding user_email (recipient: '" << user_email << "') successful." << std::endl;
}

// Bind reported_email to the second parameter (sender)
std::cout << "Binding reported_email (sender: '" << reported_email << "') to the second parameter." << std::endl;
rc = sqlite3_bind_text(stmt, 2, reported_email.c_str(), -1, SQLITE_STATIC);
if (rc != SQLITE_OK) {
    std::cerr << "SQL error (bind failed for sender): " << sqlite3_errmsg(db) << std::endl;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
} else {
    std::cout << "Binding reported_email (sender: '" << reported_email << "') successful." << std::endl;
}

// Execute the query and check if the sender exists
std::cout << "Executing SQL query to check if the sender ('" << reported_email << "') exists for recipient ('" << user_email << "')." << std::endl;
rc = sqlite3_step(stmt);
std::cout << "SQL step result code: " << rc << " (101 means no row found)." << std::endl;

if (rc == SQLITE_ROW) {
    std::cout << "Sender ('" << reported_email << "') found for recipient ('" << user_email << "')." << std::endl;
} else if (rc == SQLITE_DONE) {
    std::cout << "No sender ('" << reported_email << "') found for recipient ('" << user_email << "')." << std::endl;
} else {
    std::cerr << "SQL error (step failed): " << sqlite3_errmsg(db) << std::endl;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

// Execute the query and check if the sender exists

    
    std::cout << "Step result code: " << rc << std::endl;
   
if (rc == SQLITE_ROW) {
    std::cout << "Sender found! Proceeding to add to spam table." << std::endl;

    // Step 2: Check if the email is already reported in the spam table
    std::cout << "Checking if the email is already reported in the spam table." << std::endl;
    query = "SELECT 1 FROM spam WHERE email = ? AND report_email = ?";
    rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error (check spam table): " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return rc;
    }
    sqlite3_bind_text(stmt, 1, user_email.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, reported_email.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        // Email not already reported, proceed to insert
        std::cout << "Email not found in spam table, inserting." << std::endl;
        sqlite3_finalize(stmt);
        query = "INSERT INTO spam (email, report_email) VALUES (?, ?)";
        rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            std::cerr << "SQL error (insert into spam): " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return rc;
        }
        sqlite3_bind_text(stmt, 1, user_email.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, reported_email.c_str(), -1, SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        std::cout << "Insert into spam result code: " << rc << std::endl;
        sqlite3_finalize(stmt);
    } else {
        // Email already reported
        std::cout << "Email is already in the spam table. Skipping insert." << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Step 3: Check if reported_email exists in report_count table
    std::cout << "Checking if reported email exists in the report_count table." << std::endl;
    query = "SELECT report_count FROM report_count WHERE email = ?";
    rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error (select report_count): " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return rc;
    }
    sqlite3_bind_text(stmt, 1, reported_email.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        // Step 4: Increase the report_count by 1 if not already reported
        int current_count = sqlite3_column_int(stmt, 0);
        std::cout << "Current report count: " << current_count << ". Incrementing by 1." << std::endl;
        sqlite3_finalize(stmt);
        query = "UPDATE report_count SET report_count = report_count + 1 WHERE email = ?";
        rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            std::cerr << "SQL error (update report_count): " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return rc;
        }
        sqlite3_bind_text(stmt, 1, reported_email.c_str(), -1, SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        std::cout << "Update report_count result code: " << rc << std::endl;
        sqlite3_finalize(stmt);
    } else {
        // Step 5: Insert the reported_email with report_count = 1 if not already present
        std::cout << "No previous report count found. Inserting new entry with report_count = 1." << std::endl;
        sqlite3_finalize(stmt);
        query = "INSERT INTO report_count (email, report_count) VALUES (?, 1)";
        rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            std::cerr << "SQL error (insert into report_count): " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return rc;
        }
        sqlite3_bind_text(stmt, 1, reported_email.c_str(), -1, SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        std::cout << "Insert into report_count result code: " << rc << std::endl;
        sqlite3_finalize(stmt);
    }
    std::cout << "Email " << reported_email << " reported successfully." << std::endl;
}
else {
        std::cout << "No such sender found for the provided recipient email." << std::endl;
    }

    // Close the SQLite connection
    std::cout << "Closing database connection." << std::endl;
    sqlite3_close(db);
    return 0;
}

int ProcessREPORT(pop3User &user)
{  char invalid[] = "Invalid command";
 if(user.clientMessage.substr(0,6)=="REPORT")
    {
      vector<std::string> parts = split(user.clientMessage, '-');
      cout<<parts[1]<<endl;
      
       string b  = parts[1];
       string a = user.userEmail;
      reportEmail(a , b);
      string resp =  "Reported";
      return user.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp.c_str());
    }

    return user.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, invalid);

}
// List of functions used to process the pop3 commands from the client
execFunction funcArray[] = {
    ProcessUSER, ProcessPASS, ProcessQUIT, ProcessSTAT, ProcessLIST,
    ProcessRETR, ProcessDELE, ProcessLAST, ProcessRSET, ProcessTOP , ProcessMAIL_FROM ,ProcessRCPT_TO , ProcessDATA , ProcessREPORT
};

string commands[] = {
    "USER", "PASS", "QUIT", "STAT", "LIST", "RETR", "DELE", "NOOP", "LAST", "RSET", "TOP" 
    ,"MAIL_FROM"  , "RCPT_TO" , "DATA" , "REPORT"
};

int ProcessCMD(pop3User &User, char *clientMessage)
{
    string message = clientMessage;
    string crlf = "\r\n";  // Correct CRLF
    char resp[] = "Invalid Command";
    string email_data_ = "";
     if (User.expecting_data_) {
        // Continue capturing email content until "\r\n.\r\n"
        if (message.substr(0,1) == ".") {
            store_email_in_db_v2(User.userEmail, User.recipient, email_data_);
            User.expecting_data_ = false;
            email_data_.clear();
             string resp = "Data Stored";
            return User.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp.c_str());
        } else {
            email_data_ += message + "\r\n";  // Collect email data
            string resp = "250 ok";
        return User.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp.c_str());  // No response until data collection is done
        }
    }

    cout << "Received message: " << message << endl;
    if(message.substr(0, 4) == "SIGN" && User.state == POP3_STATE_AUTHORIZATION)
    {
      std::vector<std::string> parts = split(message, '-');
      cout<<parts[1]<<endl;
      cout<<parts[2]<<endl;
      string a  = parts[1];
      string b = parts[2];
      if(signup(a,b) == "Signup successful!")
      {
      string resp =  "250 Hello" + parts[1];
      return User.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, resp.c_str()); 
        
      } 
      
      return User.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, "singup not successful!");
    }
   
    
    
    for (int i = 0; i < sizeof(funcArray) / sizeof(funcArray[0]); i++) {
        if (strncmp(message.c_str(), commands[i].c_str(), commands[i].length()) == 0 && message.size() > 6) {
            if (message.size() >= 4 && message.substr(message.size() - 2) == crlf) {
                message.erase(message.size() - 2, 2);
            } else {
                return User.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, resp);
            }

            message = skipWhitespace(message);
            cout<<funcArray[i]<<endl;
            User.clientMessage = message;
             if (i>1 && User.state == POP3_STATE_AUTHORIZATION) {
                return User.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, "USER and PASS commands  required first");
            }

            // Only allow PASS command after USER
            

            return funcArray[i](User);
        }
    }

    return User.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, resp);
}


/////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
//////





//this function loads user details into a vector called list users. 

void *connection_handler(void *socket_desc)
{
	int newSock = *((int *)socket_desc);
    int request;
    char client_message[client_message_SIZE];

	//create a pop3user object for the current user, and send a greeting back.
	pop3User User(newSock);
	char greetings[] ="Welcome to the Pop3 webmail";
	User.SendResponse(POP3_DEFAULT_AFFERMATIVE_RESPONSE, greetings);
	/** Global variable thread count, stores number of signed users.
	we increment it once a client connects. we also place it in a mutex lock,
	to prevent race condition. **/

	sem_wait(&mutex);
	thread_count++; 
	printf(" %d Users currently online \n",thread_count);

	//optional, we can limit the number of logged in users.
	if(thread_count > 20)
	{
		char error[] ="Reached the max limit of connected users";
		User.SendResponse(POP3_DEFAULT_NEGATIVE_RESPONSE, error);
		thread_count--; 
		sem_post(&mutex);
		close(newSock);
		pthread_exit(NULL);
	}
	sem_post(&mutex);
	while(request = recv(User.get_clientSocket(), client_message, sizeof(client_message), 0) > 0)
	{
		if(ProcessCMD(User, client_message) == -1)
		{
			printf("Connection thread closing...\n");
			break;
		}
		memset(client_message, 0, sizeof(client_message));
	}
	if (request < 0) 
	{
		puts("Receive failed");
	}
	else if (request == 0)
	{
		puts("Client disconnected unexpectedly.");
	}		
	thread_count--; 
	close(newSock);
	pthread_exit(NULL);
}

//the server class
class connectServer
{
	private:
		int randomV = POP3_PORT; //the server port
		struct sockaddr_in server_address, client_address;
		int server_socket, client_socket, recvData, *thread_sock;
		char ip4[INET_ADDRSTRLEN]; // holds the client ip address
		socklen_t len; //length of the ip address

	public:
		connectServer();
		void threadHandler();
};

connectServer::connectServer()
{
    server_socket = socket(AF_INET, SOCK_STREAM, 0); //call the socket object
    if (server_socket <= 0)
    {
        perror("In sockets");
        exit(EXIT_FAILURE);
    }
	memset(&server_address, 0, sizeof server_address); 
	server_address.sin_family=AF_INET;
	server_address.sin_addr.s_addr=htonl(INADDR_ANY);
	server_address.sin_port = htons(POP3_PORT);

	//In a case the tcp port is used by another application, use a while loop to generate random 
	//port numbers until, the socket binds to the random port. This is used during 
	//development for testing, since the standard tcp client connects to port :110.
	while (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address))<0)
	{   randomV = 8080 + (rand() % 10);
        memset(&server_address, 0, sizeof server_address); 
        server_address.sin_family=AF_INET;
        server_address.sin_addr.s_addr=htonl(INADDR_ANY);
        server_address.sin_port = htons(randomV);
        
	}
}
void connectServer::threadHandler()
{
    if (listen(server_socket, 10) < 0)
    {
        perror("In listen");
        exit(EXIT_FAILURE);
    }
	//Use the infinite loop to accept new connections .
    while(1)
    { 
		len= sizeof(client_address);
		printf("Listening on TCP POP3_PORT 110: %d \n", randomV);
		
		client_socket = accept(server_socket,(struct sockaddr *)&client_address,&len);
		if(client_socket<0)
		{
			perror("Unable to accept connection");
		}
		else
		{
            inet_ntop(AF_INET, &(client_address.sin_addr), ip4, INET_ADDRSTRLEN);
			printf("Connected to ipaddress: %s\n", ip4);
		}
        pthread_t multi_thread;
        thread_sock = new int(); 
        *thread_sock = client_socket;  
		//call the thread handler
        if (pthread_create(&multi_thread, NULL, connection_handler, (void *)thread_sock) > 0) 
        {
            perror("Could not create thread");
        }           
	}
}
int main(int argc, char const *argv[])
{
	sem_init(&mutex, 0, 1); //initialize the thread mutex lock
	connectServer sserver; //declare the server object
	 //loads details of our pop3 server on startup
	sserver.threadHandler(); //call the thread handler
}