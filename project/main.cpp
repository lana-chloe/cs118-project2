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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <iomanip>
#include <netinet/tcp.h>
using namespace std;

#define PORT 5152
#define CONNECTIONS 10
#define BUF_SIZE 1024

// IPv4 packet struct
// not sure how to implement this yet
// should have a int type field such that:
  // 0 = LAN to LAN
  // 1 = LAN to WAN
  // 2 = WAN to LAN

// NAPT table entry 
struct NAPTEntry {
  string LANaddr;
  string LANprt;
  string WANprt;

  NAPTEntry(string Laddr, string Lprt, string Wprt)
    : LANaddr(Laddr), LANprt(Lprt), WANprt(Wprt) {}
};

// LAN IPs table entry 
struct LANEntry {
  string LANaddr;
  int sockfd;

  LANEntry(string Laddr, int sfd) 
    : LANaddr(Laddr), sockfd(sfd) {}
};

// UDP packet
struct UDPPacket {
  uint16_t sourcePort;
  uint16_t destinationPort;
  uint16_t checksum;
};

// TCP packet
struct TCPPacket {
  uint16_t sourcePort;
  uint16_t destinationPort;
  uint16_t checksum;
};

// NAPT Table
vector<NAPTEntry> table;
vector<LANEntry> LANtable;

// original router LAN and WAN addresses
string rLANaddr;
string rWANaddr;
string rLANsubnet;

//////////////////////
// STRUCT FUNCTIONS //
//////////////////////
LANEntry LANsearch(vector<LANEntry>& vec, string Laddr) {
    for (const auto& item : vec) {
        if (item.LANaddr == Laddr) {
            return item;
        }
    }

    // Return a default-constructed object if not found
    exit(1);
}

///////////////////////////
// FUNCTION DECLARATIONS //
///////////////////////////
// NAPT table
void configureNAPT(); 
int findEntry(string WANprt); // returns the index of the entry in the table that matches WANprt, -1 otherwise 
int findEntry(string LANaddr, string LANprt); // returns the index of the entry in the table that matches (LANaddr, LANprt), -1 otherwise
int getType(string sAddr, string dAddr); // compare src and dest addr to rLANsubnet, return 0 if LAN to LAN, 1 if LAN to WAN, and 2 if WAN to LAN

// processing packet
UDPPacket parseUDPPacket(const char* buffer); 
TCPPacket parseTCPPacket(const char* buffer);
bool parseIPPacket(const char* buffer);

// checksum
uint16_t calculateChecksum(const void* data, size_t length); 
bool verifyChecksum(uint16_t checksum, const void* data, size_t length);

// rewriting and forwarding
char* rewritePacket(char* buffer); 
void forwardPacket(char* buffer, int bytesRead); 
void handleClient(int clientSocket); 

int main() {
  configureNAPT();

  // TCP setup 
  int serverSocket, maxSocket, activity, clientSocket;
  struct sockaddr_in serverAddress, clientAddress;
  socklen_t clientLength;

  // Create a socket
  serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket < 0) {
    perror("Error creating socket");
    return 1;
  }

  // set SO_REUSEPORT
  int optval = 1;
  setsockopt(serverSocket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

  // Bind the socket to a specific IP and port
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_addr.s_addr = INADDR_ANY;
  serverAddress.sin_port = htons(PORT);

  if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
    perror("Error binding socket");
    return 1;
  }

  // Start listening for incoming connections
  if (listen(serverSocket, 5) < 0) {
    perror("Error listening for connections");
    return 1;
  }

  cout << "Server listening on port 5152..." << endl;

  fd_set readFds;
  vector<int> clientSockets;

  // Initialize the set of client sockets
  FD_ZERO(&readFds);
  FD_SET(serverSocket, &readFds);
  maxSocket = serverSocket;
  int index = 0;

  while (true) {
    // Copy the set of sockets to select
    fd_set tempFds = readFds;

    // Call select() to monitor the sockets
    activity = select(maxSocket + 1, &tempFds, nullptr, nullptr, nullptr);
    if (activity < 0) {
      perror("Error in select");
      return 1;
    }

    // Check for activity on the server socket
    if (FD_ISSET(serverSocket, &tempFds)) {
      // Accept incoming connections
      clientLength = sizeof(clientAddress);
      clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientLength);
      if (clientSocket < 0) {
        perror("Error accepting connection");
        continue;
      }

      // Add the new client socket to the set
      clientSockets.push_back(clientSocket);
      FD_SET(clientSocket, &readFds);
      // map sock fd to LAN address
      LANtable[index].sockfd = clientSocket;

      // Update the maximum socket value
      if (clientSocket > maxSocket) {
        maxSocket = clientSocket;
      }

      cout << LANtable[index].LANaddr << " " << LANtable[index].sockfd << endl;
      cout << "New connection, socket fd is " << clientSocket << ", IP is : " << inet_ntoa(clientAddress.sin_addr) << ", port : " << ntohs(clientAddress.sin_port) << endl;
    }

    // Check for activity on client sockets
    for (int i = 0; i < clientSockets.size(); ++i) {
      int socketFd = clientSockets[i];

      if (FD_ISSET(socketFd, &tempFds)) {
        // Handle data from the client
        handleClient(socketFd);

        // Remove the client socket from the set
        //FD_CLR(socketFd, &readFds);
        //clientSockets.erase(clientSockets.begin() + i);
      }
    }

    index++;
  }

  // Close the server socket
  close(serverSocket);

  return 0;
}

void configureNAPT() {
  string szLine;
  int line = 1;

  while (getline(cin, szLine)) {
    // first line is the router's LAN IP and the WAN IP
    if (line == 1) {
      size_t dwPos = szLine.find(' ');
      rLANaddr = szLine.substr(0, dwPos);
      rWANaddr = szLine.substr(dwPos + 1);

      //After getting router's LAN IP, set rLANsubnet to the first 3 bytes of rLANaddr:
      size_t firstdot = rLANaddr.find('.'); // first . char
      size_t seconddot = rLANaddr.find('.', firstdot + 1); // second . char
      size_t thirddot = rLANaddr.find('.', seconddot + 1); // third . char
      rLANsubnet = rLANaddr.substr(0, thirddot);
    }
    // get to NAPT table section
    else if (szLine.find(' ') != string::npos) {
      size_t first = szLine.find(' '); // first space char
      size_t second = szLine.find(' ', first + 1); // second space char
      size_t end = szLine.size();

      string LANaddr = szLine.substr(0, first);
      string LANprt = szLine.substr(first + 1, second - first - 1);
      string WANprt = szLine.substr(second + 1, end - second - 2);

      NAPTEntry napt(LANaddr, LANprt, WANprt);
      table.push_back(napt);
    }
    // get to LAN IP section
    else if (!szLine.empty()) {
      LANEntry lan(szLine, 0);
      LANtable.push_back(lan);
    }

    line++;
  }

  // print NAPT table
  for (const auto& entry : table) {
    cout << entry.LANaddr << " " << entry.LANprt << " " << entry.WANprt << endl;
  }

  // print LAN IP table
  for (const auto& entry : LANtable) {
    cout << entry.LANaddr << " " << entry.sockfd << endl;
  }
}

int findEntry(string WANprt) {
  for (unsigned int i = 0; i < table.size(); i++) {
    if (WANprt.compare(table.at(i).WANprt) == 0) {
      return i;
    }
  }
  return -1;
}

int findEntry(string LANaddr, string LANprt) {
  for (unsigned int i = 0; i < table.size(); i++) {
    if (LANprt.compare(table.at(i).LANprt) == 0 && LANaddr.compare(table.at(i).LANaddr) == 0) {
      return i;
    }
  }
  return -1;
}

// NOTE: no checking of whether addresses are valid; classify an address as LAN if the 1st three bytes match rLANsubnet, classify as WAN otherwise
// IMPLEMENT CHECK!!!
int getType(string sAddr, string dAddr) { 
  size_t firstdot = sAddr.find('.'); // first . char
  size_t seconddot = sAddr.find('.', firstdot + 1); // second . char
  size_t thirddot = sAddr.find('.', seconddot + 1); // third . char

  string truncSaddr = sAddr.substr(0, thirddot);

  firstdot = dAddr.find('.'); // first . char
  seconddot = dAddr.find('.', firstdot + 1); // second . char
  thirddot = dAddr.find('.', seconddot + 1); // third . char

  string truncDaddr = dAddr.substr(0, thirddot);

  int src = 0;
  int dst = 0;
  if (rLANsubnet.compare(truncSaddr) == 0)
    src = 1;
  if (rLANsubnet.compare(truncDaddr) == 0)
    dst = 1;
  
  if (src == 1 && dst == 1) //LAN to LAN
    return 0;
  else if (src == 1 && dst == 0) //LAN to WAN
    return 1;
  else //WAN to LAN
    return 2;
}

UDPPacket parseUDPPacket(const char* buffer) {
  const udphdr* udpHeader = reinterpret_cast<const udphdr*>(buffer);

  UDPPacket udpPacket;
  udpPacket.sourcePort = ntohs(udpHeader->source);
  udpPacket.destinationPort = ntohs(udpHeader->dest);
  udpPacket.checksum = ntohs(udpHeader->check);

  return udpPacket;
}

TCPPacket parseTCPPacket(const char* buffer) {
  const tcphdr* tcpHeader = reinterpret_cast<const tcphdr*>(buffer);

  TCPPacket tcpPacket;
  tcpPacket.sourcePort = ntohs(tcpHeader->source);
  tcpPacket.destinationPort = ntohs(tcpHeader->dest);
  tcpPacket.checksum = ntohs(tcpHeader->check);

  return tcpPacket;
}

uint16_t calculateChecksum(const void* data, size_t length) {
  const uint16_t* buffer = static_cast<const uint16_t*>(data);
  size_t size = length;
  uint32_t sum = 0;

  while (size > 1) {
    sum += *buffer++;
    size -= sizeof(uint16_t);
  }
  if (size == 1) {
    uint16_t value = *(reinterpret_cast<const uint8_t*>(buffer));
    sum += value;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return static_cast<uint16_t>(~sum);
}

void forwardPacket(char* buffer, int bytesRead) {
  ip* ipHeader = reinterpret_cast<ip*>(buffer);
  char* destIp = inet_ntoa(ipHeader->ip_dst);
  --ipHeader->ip_ttl; // decrement ttl field
  ipHeader->ip_sum = 0;
  ipHeader->ip_sum = calculateChecksum(ipHeader, ipHeader->ip_hl * 4); // recalculate checksum

  char* ipH = reinterpret_cast<char*>(ipHeader);
  memcpy(buffer, ipH, strlen(ipH));

  cout << hex << setfill('0');
  for (size_t i = 0; i < bytesRead; ++i) {
      cout << setw(2) << static_cast<int>(reinterpret_cast<uint8_t*>(buffer)[i]) << " ";
  }
  cout << dec << endl;

  // forward packet
  LANEntry forward = LANsearch(LANtable, destIp);
  send(forward.sockfd, buffer, bytesRead, 0);

}

void handleClient(int clientSocket) {
  char buffer[1024];
  int bytesRead;

  bytesRead = read(clientSocket, buffer, sizeof(buffer));

  if (bytesRead < 0) {
    perror("Error reading from socket");
    //close(clientSocket);
    return;
  }
  if (bytesRead == 0) {
    // Client disconnected
    //close(clientSocket);
    return;
  }

  buffer[bytesRead] = '\0';

  // SEND (hex)
  for (int i = 0; i < bytesRead; ++i) {
    cout << hex << setw(2) << setfill('0') << (static_cast<int>(buffer[i]) & 0xFF) << " ";
  }
  cout << dec << endl;

  forwardPacket(buffer, bytesRead);

  //close(clientSocket);
}