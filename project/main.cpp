#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <arpa/inet.h>
#include <sys/select.h>
using namespace std;

#define PORT 5152
#define CONNECTIONS 10
#define BUF_SIZE 1024

// IPv4 packet struct
struct IPv4Packet {
  string srcAddr;
  string destAddr;
  uint8_t TTL;
  uint16_t checksum;

  int type;
  // 0 = LAN to LAN
  // 1 = LAN to WAN
  // 2 = WAN to LAN

  IPv4Packet(string sAddr, string dAddr, uint8_t TTL, uint16_t cs, int tp)
    : srcAddr(sAddr), destAddr(dAddr), TTL(TTL), checksum(cs), type(tp) {}
};

// NAPT table entry struct
struct NAPTEntry {
  string LANaddr;
  string LANprt;
  string WANprt;

  NAPTEntry(string Laddr, string Lprt, string Wprt)
    : LANaddr(Laddr), LANprt(Lprt), WANprt(Wprt) {}
};

// LAN IPs table entry struct
struct LANEntry {
  string LANaddr;
  string LANprt;

  LANEntry(string Laddr, string Lprt) 
    : LANaddr(Laddr), LANprt(Lprt) {}
};

// NAPT Table
vector<NAPTEntry> table;

// router LAN and WAN addresses
string rLANaddr;
string rWANaddr;

void configureNAPT() {
  string szLine;
  int line = 1;

  while (getline(cin, szLine)) {
      // first line is the router's LAN IP and the WAN IP
      if (line == 1) {
        size_t dwPos = szLine.find(' ');
        rLANaddr = szLine.substr(0, dwPos);
        rWANaddr = szLine.substr(dwPos + 1);
        //cout << "rLANaddr: " << rLANaddr << endl;
        //cout << "rWANaddr: " << rWANaddr << endl;
      }
      // get to NAPT table section
      else if (szLine.find(' ') != string::npos) {
        size_t first = szLine.find(' '); // first space char
        size_t second = szLine.find(' ', first + 1); // second space char
    
        // extract three substrings
        string LANaddr = szLine.substr(0, first);
        string LANprt = szLine.substr(first + 1, second - first - 1);
        string WANprt = szLine.substr(second + 1);

        //cout << "LANaddr: " << LANaddr << endl;
        //cout << "LANprt: " << LANprt << endl;
        //cout << "WANprt: " << WANprt << endl;

        // add to NAPT table
        NAPTEntry entry(LANaddr, LANprt, WANprt);
        table.push_back(entry);
      }

      line++;
  }
}

int handleClient(int clientSocket) {
  char buf[BUF_SIZE];
  int bytesRead;

  bytesRead = read(clientSocket, buf, sizeof(buf));

  if (bytesRead < 0) {
    perror("Error reading from socket");
    close(clientSocket);
    return 1;
  }

  if (bytesRead == 0) {
    // client disconnected
    close(clientSocket);
    return 1;
  }

  buf[bytesRead] = '\0';
  cout << "Received message from client " << clientSocket << ": " << buf << endl;
  return 0;
}

int main() {
  // TCP setup
  int serverSocket, maxSocket, activity, clientSocket;
  struct sockaddr_in serverAddress, clientAddress;
  socklen_t clientLength;

  // create a socket
  serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket < 0) {
    perror("Error creating socket");
    return 1;
  }

  // set SO_REUSEPORT
  int optval = 1;
  setsockopt(serverSocket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

  // bind the socket to a specific IP and port
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_addr.s_addr = INADDR_ANY;
  serverAddress.sin_port = htons(PORT);

  if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
    perror("Error binding socket");
    return 1;
  }

  // start listening for incoming connections
  if (listen(serverSocket, 5) < 0) {
    perror("Error listening for connections");
    return 1;
  }

  cout << "Server listening on port 5152..." << endl;

  fd_set readFds;
  vector<int> clientSockets;

  // initialize the set of client sockets
  FD_ZERO(&readFds);
  FD_SET(serverSocket, &readFds);
  maxSocket = serverSocket;

  // TCP server can handle multiple connections...
  while (true) {
    // copy the set of sockets to select
    fd_set tempFds = readFds;

    // call select() to monitor the sockets
    activity = select(maxSocket + 1, &tempFds, NULL, NULL, NULL);

    if (activity < 0) {
      perror("Error in select");
      return 1;
    }

    // check for activity on the server socket
    if (FD_ISSET(serverSocket, &tempFds)) {
      // accept incoming connections
      clientLength = sizeof(clientAddress);
      clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientLength);

      if (clientSocket < 0) {
        perror("Error accepting connection");
        continue;
      }

      // add the new client socket to the set
      clientSockets.push_back(clientSocket);
      FD_SET(clientSocket, &readFds);

      // update the maximum socket value
      if (clientSocket > maxSocket) {
        maxSocket = clientSocket;
      }

      cout << "New connection, socket fd is " << clientSocket << ", IP is : " << inet_ntoa(clientAddress.sin_addr) << ", port : " << ntohs(clientAddress.sin_port) << endl;
    }

    // check for activity on client sockets
    for (int i = 0; i < clientSockets.size(); ++i) {
      int socketFd = clientSockets[i];

      if (FD_ISSET(socketFd, &tempFds)) {
        if(handleClient(socketFd) == 1) {
          // remove the client socket from the set
          FD_CLR(socketFd, &readFds);
          clientSockets.erase(clientSockets.begin() + i);
        }
      }
    }
  }

  close(serverSocket);

  return 0;
}
