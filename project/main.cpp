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
  string LANprt;

  LANEntry(string Laddr, string Lprt) 
    : LANaddr(Laddr), LANprt(Lprt) {}
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

// original router LAN and WAN addresses
string rLANaddr;
string rWANaddr;
string rLANsubnet;

// FUNCTION DECLARATIONS //
void configureNAPT();
int findEntry(string WANprt); // returns the index of the entry in the table that matches WANprt, -1 otherwise 
int findEntry(string LANaddr, string LANprt); // returns the index of the entry in the table that matches (LANaddr, LANprt), -1 otherwise
int getType(string sAddr, string dAddr); // compare src and dest addr to rLANsubnet, return 0 if LAN to LAN, 1 if LAN to WAN, and 2 if WAN to LAN
UDPPacket parseUDPPacket(const char* buffer); // parse UDP packet
TCPPacket parseTCPPacket(const char* buffer); // parse TCP packet
void parseIPPacket(const char* buffer); // parse IP packet
uint16_t calculateChecksum(const void* data, size_t length); // calculate checksum
bool verifyChecksum(uint16_t checksum, const void* data, size_t length); // compare calculated checksum with checksum field
int handleClient(int clientSocket); // get message from client socket

int main() {
  // configure NAPT table
  //configureNAPT();

  /*cout << "LAN to LAN returns type " << getType("192.168.1.200", "192.168.1.100") << endl;
  cout << "LAN to WAN returns type " << getType("192.168.1.200", rWANaddr) << endl;
  cout << "LAN to LAN returns type " << getType("192.168.1.200", rLANaddr) << endl;
  cout << "WAN to LAN returns type " << getType(rWANaddr, rLANaddr) << endl;*/

  /*cout << "Entry for WANprt # 8080 is found at " << findEntry("8080") << endl;
  cout << "Entry for WANprt # 443 is found at " << findEntry("443") << endl;
  cout << "Entry for WANprt # 123 is found at " << findEntry("123") << endl;

  cout << "\n" << endl;

  cout << "Entry for LANaddr 192.168.1.300 and LANprt 8080 is found at " << findEntry("192.168.1.300", "8080") << endl;
  cout << "Entry for LANaddr 192.168.1.100 and LANprt 8080 is found at " << findEntry("192.168.1.100", "8080") << endl;
  cout << "Entry for LANaddr 192.168.1.200 and LANprt 9000 is found at " << findEntry("192.168.1.200", "9000") << endl;*/

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

      //After getting router's LAN IP, set rLANsubnet to the first 3 bytes of rLANaddr:
      size_t firstdot = rLANaddr.find('.'); // first . char
      size_t seconddot = rLANaddr.find('.', firstdot + 1); // second . char
      size_t thirddot = rLANaddr.find('.', seconddot + 1); // third . char
      rLANsubnet = rLANaddr.substr(0, thirddot);

      cout << "rLANsubnet: " << rLANsubnet << endl;
    }
    // get to NAPT table section
    else if (szLine.find(' ') != string::npos) {
      size_t first = szLine.find(' '); // first space char
      size_t second = szLine.find(' ', first + 1); // second space char
      size_t end = szLine.size();

      // extract three substrings
      string LANaddr = szLine.substr(0, first);
      string LANprt = szLine.substr(first + 1, second - first - 1);
      string WANprt = szLine.substr(second + 1, end - second - 2);

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

void parseIPPacket(const char* buffer) {
  const ip* ipHeader = reinterpret_cast<const ip*>(buffer);

  string sourceIP = inet_ntoa(ipHeader->ip_src);
  string destinationIP = inet_ntoa(ipHeader->ip_dst);
  uint16_t checksum = ntohs(ipHeader->ip_sum);
  uint8_t protocol = ipHeader->ip_p;

  if (protocol == IPPROTO_UDP) {
    UDPPacket udpPacket = parseUDPPacket(buffer + ipHeader->ip_hl * 4);
    // check what IPv4 type it is
  } else if (protocol == IPPROTO_TCP) {
    TCPPacket tcpPacket = parseTCPPacket(buffer + ipHeader->ip_hl * 4);
    // check what IPv4 type it is
  } else {
    perror("Unknown Protocol");
    exit(1);
  }
}

uint16_t calculateChecksum(const void* data, size_t length) {
  return 0;
}

bool verifyChecksum(uint16_t checksum, const void* data, size_t length) {
  uint16_t calculatedChecksum = calculateChecksum(data, length);
  return checksum == calculatedChecksum;
}

int handleClient(int clientSocket) {
  char buffer[BUF_SIZE];
  int bytesRead;

  bytesRead = read(clientSocket, buffer, sizeof(buffer));

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

  buffer[bytesRead] = '\0';

  cout << "Received message:\n" << buffer << endl;
  
  parseIPPacket(buffer);

  return 0;
}