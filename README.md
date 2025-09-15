# 2025-secure-programming-chat-system

### How to use

## 1. Clone the repository
    git clone <repository_url>
    cd 2025-secure-programming-chat-system


## 2. Create a virtual environment

    # On Windows
    python -m venv venv
    venv\Scripts\activate

    # On macOS/Linux
    python3 -m venv venv
    source venv/bin/activate

## 3. Install dependencies
    pip install -r requirements.txt


## Running the Server
Start the P2P server with:

    python serverP2P.py

## Running the Client

Start the P2P client with:

    python clientP2P.py

Enter your username when prompted.

Available commands:

    chat <recipient> <message>  - send a message to a user or 'Group'
    history [user]              - show message history with a user, or all unread messages if no user specified
    whoami                      - show your current username
    ping                        - ping the server
    list                        - list all connected users
    quit                        - exit the client
    help or -help               - show this help message

Unread messages are displayed with a [NEW] tag.