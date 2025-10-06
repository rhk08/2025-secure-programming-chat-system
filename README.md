# 2025-secure-programming-chat-system

Note this is the version of our chat system WITH vulnerabilities. 

### How to use

## 1. Clone the repository
    git clone <repository_url>
    cd 2025-secure-programming-chat-system

### OR unzip the repository from a .zip file

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

If connecting to another device on LAN, replace the "host" IP address with the private IP address of the device you wish to connect to.

Ensure that each device connects to a different port.
        
For example:

        {
            "host": "HOST DEVICE IP ADDRESS",
            "port": 9001,
            "private_key": "..."
        },


## Running the Server

You must start with at least one server in --intro mode for the P2P network to work, if you are testing it on a single machine include the --local argument when starting up the server.

Note: if you experience issues finding the introducer or acting as an introducer make sure to edit the bootstrap_servers.json to match the port you opened the server on and the ipaddress, see Step 4. in the "How to use" section for more detailed instructions (REMEMBER the --local argument sets the ip address to 127.0.0.1)

To run the server as an introducer across a LAN network (default), use:

    python server_v1-3.py [port number] --intro

To run the server as an introducer on your local machine, use:

    python server_v1-3.py [port number] --intro --local



See the "Update bootstrap_servers.json" section if you have issues 


Start a non introducer P2P server with:

    python server_v1-3.py [port number]



## Running the Client

Start the P2P client with:

    python client_v1-3.py

To test locally running clients on different machines, use:

    python client_v1-3.py ws://[host]:[port]

You will automatically connect to a server and assigned a UUID

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

## Common Issues

### Issue 1:

If you recieved:

    OSError: [Errno 10048] error while attempting to bind on address...

This means you are already using that port for another server Locally

### Issue 2:

If you ran the line:
    
    python server_v1-3.py 9001 --intro

And recieved:
    
    ValueError("No matching introducer found")
        
This means you have not changed the boostrap_servers.json and cannot assume the role of an introducer, see the "How to Use" section for more detail.

## Need any help? Please contact a member of our group
ryan.khor@student.adelaide.edu.au

lucy.fidock@student.adelaide.edu.au

luke.schaefer@adelaide.edu.au

a1870629@adelaide.edu.au

nelson.then@student.adelaide.edu.au


