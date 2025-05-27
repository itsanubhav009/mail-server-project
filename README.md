# Mail Server Project

## Overview

This project implements a custom mail server primarily in C++, featuring POP3-like access, email storage, user management, and several advanced domain administration and security features. It utilizes a SQLite database for persistent storage and a multithreaded architecture to handle concurrent client connections. The project also includes JavaScript components, potentially for client interaction or auxiliary mail services.

## Features

*   **POP3 Core Functionality**:
    *   Supports standard commands: `USER`, `PASS`, `QUIT`, `STAT`, `LIST`, `RETR`, `DELE`, `NOOP`, `RSET`, `TOP`.
    *   Session state management (Authorization, Transaction, Update).
*   **Email Handling**:
    *   Receiving and storing emails with content and metadata.
    *   Marking emails for deletion.
    *   Attachment handling (Base64 decoding and file storage).
*   **User Management**:
    *   User signup with email and password.
    *   Secure credential storage (details to be added based on hashing if any).
    *   Mailbox locking mechanism.
*   **SQLite Backend**:
    *   Stores user accounts, emails, domain registrations, access control lists, and spam reports.
*   **Advanced Domain & Access Control (Custom Commands)**:
    *   **Domain Registration**: Users can register new domains (e.g., `yourcompany.com`), becoming its administrator. A unique passkey is generated for domain administration.
    *   **Domain Access via Passkey**: Users can gain access to send/receive mail under a registered domain by providing its passkey.
    *   **Inter-Domain Trust**: Administrators of one domain can grant other registered domains permission to interact (e.g., send mail as if from that domain, specifics TBD).
    *   **User-Level Domain Permissions**: Domain administrators can grant or revoke specific users' rights to use the domain.
    *   **Passkey Management**: Domain administrators can change their domain's passkey.
*   **Security Features (Custom Commands)**:
    *   **Spam Reporting**: Users can report emails as spam, with a system to track report counts against offending senders.
*   **Networking**:
    *   Listens on the standard POP3 port (110) with fallback to other ports.
    *   Handles multiple clients concurrently using Pthreads.
*   **JavaScript Components**:
    *   (To be detailed: e.g., Client application, Nodemailer integration for outbound SMTP, etc.)

## System Design

### Core C++ Server

The heart of the system is a multithreaded C++ application that listens for client connections on a TCP socket.

1.  **Connection Handling**:
    *   The `connectServer` class initializes a socket and listens for incoming connections.
    *   Upon a new connection, `threadHandler` accepts it and spawns a new POSIX thread (`pthread`) managed by the `connection_handler` function.
    *   A `pop3User` object is instantiated for each connected client to manage their session state and data.
    *   A semaphore (`mutex`) is used to safely increment/decrement a global `thread_count`.

2.  **Command Processing (`ProcessCMD`)**:
    *   Client messages are received and parsed.
    *   A central `ProcessCMD` function routes commands to specific handler functions (e.g., `ProcessUSER`, `ProcessPASS`, `ProcessMAIL_FROM`, `ProcessREGISTER`).
    *   The server maintains the client's state (`POP3_STATE_AUTHORIZATION`, `POP3_STATE_TRANSACTION`, `POP3_STATE_UPDATE`). Certain commands are only valid in specific states.

3.  **Authentication and Authorization (`ProcessUSER`, `ProcessPASS`, `SIGN`, `SIGN_P`)**:
    *   `USER`: Client specifies their email. The server checks if the user exists in the `user` table.
    *   `PASS`: Client sends their password. The server verifies it against the stored password for the given email. Successful authentication transitions the state to `POP3_STATE_TRANSACTION`.
    *   `SIGN`: Allows new users to register with an email and password (for the default "example.com" or non-passkey protected domains).
    *   `SIGN_P`: Allows new users to register for a specific domain by providing the domain's `passkey` (obtained via `REGISTER` or given by an admin).

4.  **Mail Operations (`ProcessLIST`, `ProcessRETR`, `ProcessDELE`, etc.)**:
    *   These functions query the `emails` table, scoped by the authenticated user's ID.
    *   `RETR` fetches email content.
    *   `DELE` marks emails as `deleted = 1` in the database. Changes are finalized during the `UPDATE` state (on `QUIT`).

5.  **Email Submission Flow (Custom: `MAIL_FROM`, `RCPT_TO`, `DATA`)**:
    *   This flow mimics SMTP for a client to submit an email.
    *   `MAIL_FROM`: Client declares the sender. Server validates if the sender matches the authenticated user or if the user has appropriate domain permissions.
    *   `RCPT_TO`: Client declares the recipient. The server checks if the recipient exists. For cross-domain sending, it verifies permissions using `domain_acess` (domain-to-domain trust) or `email_acess` (user-to-domain permission) tables.
        *   If the recipient is `example.com`, it's likely treated as a local delivery.
        *   For other domains, the server checks if the sender's domain (`a[1]`) is the same as the recipient's domain (`t[1]`) OR if an entry exists in `email_acess` (user `user.userEmail` has access to domain `t[1]`) OR if an entry exists in `domain_acess` (sender's domain `a[1]` has access to recipient's domain `t[1]`).
    *   `DATA`: Client sends this command, and the server responds with a "start mail input" message.
    *   The server then enters `expecting_data_` mode, accumulating lines until a line with a single `.` is received.
    *   The collected email data is stored via `store_email_in_db_v2`.

6.  **Attachment Handling (`SENDATTACHMENT`)**:
    *   Client sends `SENDATTACHMENT:filename:base64_encoded_content_chunk`.
    *   The server enters `recieving_attach` mode.
    *   `process_attachment_command` prepares a unique filename.
    *   Subsequent data chunks are appended to a buffer (`recieve`) until an `EOF` marker.
    *   `write_content_to_file` writes the decoded data.
    *   `store_email_in_db` saves the file path.

7.  **Domain Management & Access Control (Custom Commands like `REGISTER`, `GETACCESS`, `ADDDOMAINACCESS`, `ADDE`)**:
    *   These commands interact with `admin_panel`, `domain_acess`, and `email_acess` tables.
    *   `REGISTER`: Adds a new domain and its creator's email to `admin_panel` with a generated passkey.
    *   `GETACCESS`: A user provides a domain and its passkey. If valid, the user's email is added to `email_acess` for that domain, granting them permission.
    *   `ADDDOMAINACCESS`: An admin of `domaina` (verified via `check_domain_register`) can add an entry to `domain_acess` allowing `domaina` to operate with `domain`. Both domains must be registered in `admin_panel`.
    *   `ADDE`: An admin of `domain` (verified via `check_domain_register`) can add `user_to_add_email` to `email_acess` for that `domain`. The `user_to_add_email` must exist.

8.  **Database Schema (Inferred)**:
    *   `user (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, locked INTEGER DEFAULT 0)`
    *   `emails (id INTEGER PRIMARY KEY, user_id INTEGER, sender TEXT, recipient TEXT, subject TEXT, data TEXT, size INTEGER, date_sent TEXT, deleted INTEGER DEFAULT 0, content TEXT)` (Note: `data` might be file path for attachments, `content` for email body)
    *   `admin_panel (id INTEGER PRIMARY KEY, email TEXT, domain TEXT UNIQUE, passkey TEXT)`
    *   `domain_acess (id INTEGER PRIMARY KEY, domaina TEXT, domain TEXT)` (Grants `domaina` access to `domain`)
    *   `email_acess (id INTEGER PRIMARY KEY, email TEXT, domain TEXT)` (Grants `email` access to `domain`)
    *   `spam (id INTEGER PRIMARY KEY, email TEXT, report_email TEXT)`
    *   `report_count (id INTEGER PRIMARY KEY, email TEXT UNIQUE, report_count INTEGER DEFAULT 0)`

### JavaScript/Node.js Components

*   **(Please describe the role of `index.js` and any other JavaScript files. How do they interact with the C++ server, if at all? What is `nodemailer` used for?)**
    *   Example: "The `index.js` file provides a command-line interface (CLI) client to connect to the C++ mail server, send commands, and manage emails."
    *   Example: "Nodemailer is used by a separate Node.js script to forward emails received by the C++ server to external mail systems if the recipient domain is not local."

## Tech Stack

*   **Core Server**: C++
    *   Standard libraries: `<iostream>`, `<string>`, `<vector>`, `<filesystem>`, `<cstring>`, `<sstream>`, `<algorithm>`, etc.
    *   Networking: POSIX sockets (`<sys/socket.h>`, `<arpa/inet.h>`)
    *   Threading: Pthreads (`<pthread.h>`)
    *   Synchronization: Semaphores (`<semaphore.h>`)
*   **Database**: SQLite 3
*   **Auxiliary/Client (Potentially)**: JavaScript/Node.js
    *   (List any Node.js packages like `nodemailer` if used for a specific purpose)

## Prerequisites

*   **C++ Compiler**: A C++ compiler that supports C++17 (for `<filesystem>`) or adjust as needed (e.g., g++).
*   **SQLite3**: SQLite3 library and development headers (e.g., `libsqlite3-dev` on Debian/Ubuntu).
*   **Make (Optional)**: If a Makefile is provided.
*   **Node.js & npm (If JS components are used)**: Latest LTS version recommended.

## Installation & Setup

### 1. C++ Server

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/itsanubhav009/mail-server-project.git
    cd mail-server-project
    ```
2.  **Compile the server**:
    *(You'll need to provide the compilation command. Example below, adjust as necessary)*
    ```bash
    g++ -std=c++17 mail/final_server.cpp mail/globals.h -o mail_server -lsqlite3 -lpthread 
    ```
    *   (If there are other `.cpp` or `.h` files involved in `mail/globals.h` or linked, they need to be included in the command).
3.  **Database Setup**:
    *   The server attempts to open/create `mailserver.db` in the current directory.
    *   The necessary tables (`user`, `emails`, `admin_panel`, `domain_acess`, `email_acess`, `spam`, `report_count`) should be created if they don't exist. *(It seems the C++ code does not explicitly create these tables if they are missing, relying on them to exist. You might need to provide SQL for initial table creation or confirm if the C++ code handles this.)*

    Example SQL for table creation (add this to the README or a setup script):
    ```sql
    CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        locked INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, -- Should be FOREIGN KEY REFERENCES user(id)
        sender TEXT,
        recipient TEXT,
        subject TEXT, -- Assuming subject is part of 'data' or needs a column
        data TEXT,    -- For email body or attachment path
        size INTEGER,
        date_sent TEXT, -- Consider using DATETIME type
        deleted INTEGER DEFAULT 0,
        content TEXT  -- Or merge with 'data'
    );

    CREATE TABLE IF NOT EXISTS admin_panel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        domain TEXT UNIQUE NOT NULL,
        passkey TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS domain_acess ( -- Potential typo: domain_access
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domaina TEXT NOT NULL, -- Admin's domain
        domain TEXT NOT NULL   -- Accessed domain
    );

    CREATE TABLE IF NOT EXISTS email_acess ( -- Potential typo: email_access
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        domain TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS spam (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,        -- User who reported
        report_email TEXT NOT NULL  -- The email address being reported
    );

    CREATE TABLE IF NOT EXISTS report_count (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL, -- The email address that was reported
        report_count INTEGER DEFAULT 0
    );
    ```

4.  **Create Attachment Storage Directory**:
    ```bash
    mkdir -p store
    ```

### 2. JavaScript Components (If Applicable)

*   **(Provide setup steps for the JS part, e.g., `npm install`)**

## Usage

### 1. Running the C++ Server

```bash
./mail_server
