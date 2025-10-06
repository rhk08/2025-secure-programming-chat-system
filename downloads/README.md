# 2025-secure-programming-chat-system

    Note this is the version of our chat system WITH vulnerabilities. 

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

## 4. Update bootstrap_servers.json
    Modify the bootstrap_servers.json file to include the ip addresses and port numbers of servers to connect to via bootstrap.

        If connecting to another device, replace the "host" IP address with the IP address of the device you wish to connect to.

        Ensure that each device connects to a different port.
        
        For example:
        {
            "host": "HOST DEVICE IP ADDRESS",
            "port": 9001,
            "private_key": "..."
        },

## Running the Server
Start the P2P server with:

    python server_v1-3.py [port number]

To run the server as the introducer, use:

    python server_v1-3.py [port number] --intro

## Running the Client

Start the P2P client with:

    python client_v1-3.py

To test locally running clients on different machines, use:

    python client_v1-3.py ws://[host]:[port]

Enter your username when prompted.

[i] Available commands:
  chat <recipient> <message>   - send a message to a user
  sendfile <recipient> <path>  - send a file to a user (DM)
  all <message>                - send a group message
  add <uuid> <nickname>        - add a user as a friend
  friends                      - shows a list of your friends
  whoami                       - show your current UUID
  list                         - shows all current users
  quit | q                     - exit
  help | -h                    - show this help

Unread messages are displayed with a [NEW] tag.

## Need any help? Please contact a member of our group
ryan.khor@student.adelaide.edu.au
lucy.fidock@student.adelaide.edu.au
luke.schaefer@adelaide.edu.au
a1870629@adelaide.edu.au
nelson.then@student.adelaide.edu.au