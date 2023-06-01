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

// IPv4 packet types
  // 0 = LAN to LAN
  // 1 = LAN to WAN
  // 2 = WAN to LAN

// NAPT table entry 
struct NAPTentry {
  string LANaddr;
  string LANprt;
  string WANprt;

  NAPTentry(string Laddr, string Lprt, string Wprt)
    : LANaddr(Laddr), LANprt(Lprt), WANprt(Wprt) {}
};

// LAN IPs table entry 
struct LANentry {
  string LANaddr;
  int sockfd;

  LANentry(string Laddr, int sfd) 
    : LANaddr(Laddr), sockfd(sfd) {}
};

// NAPT Table
vector<NAPTentry> table;
vector<LANentry> LANtable;

// original router LAN and WAN addresses
string rLANaddr;
string rWANaddr;
string rLANsubnet;

//////////////////////
// STRUCT FUNCTIONS //
//////////////////////
LANentry LANsearch(vector<LANentry>& vec, string Laddr) {
  for (const auto& item : vec) {
    if (item.LANaddr == Laddr) {
      return item;
    }
  }

  perror("LANentry not found.");
  exit(1);
}

NAPTentry NAPTsearch(vector<NAPTentry>& vec, string Laddr, int Lprt) {
  string LANprt = to_string(Lprt);

  for (const auto& item : vec) {
    if (item.LANaddr == Laddr && item.LANprt == LANprt) {
      return item;
    }
  }

  perror("NAPTentry not found.");
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

// checksum
uint16_t csum(const void* data, size_t length); // calculate checksum
bool vCsum(uint16_t checksum, const void* data, size_t length); // verify checksum

// rewriting and forwarding
void rewrite(char* buffer); 
void forward(char* buffer, int bytesRead); 
void handleClient(int clientSocket); 

int main() {
  configureNAPT();

  // TCP setup 
  int serverSocket, maxSocket, activity, clientSocket;
  struct sockaddr_in serverAddress, clientAddress;
  socklen_t clientLength;

  serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket < 0) {
    perror("Error creating socket");
    return 1;
  }

  int optval = 1;
  setsockopt(serverSocket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

  serverAddress.sin_family = AF_INET;
  serverAddress.sin_addr.s_addr = INADDR_ANY;
  serverAddress.sin_port = htons(PORT);

  if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
    perror("Error binding socket");
    return 1;
  }

  if (listen(serverSocket, 5) < 0) {
    perror("Error listening for connections");
    return 1;
  }

  //cout << "Server listening on port 5152..." << endl;

  fd_set readFds;
  vector<int> clientSockets;

  // initialize the set of client sockets
  FD_ZERO(&readFds);
  FD_SET(serverSocket, &readFds);
  maxSocket = serverSocket;
  int index = 0;

  while (true) {
    fd_set tempFds = readFds;

    // call select() to monitor the sockets
    activity = select(maxSocket + 1, &tempFds, nullptr, nullptr, nullptr);
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
      LANtable[index].sockfd = clientSocket; // map sock fd to LAN address

      // update the maximum socket value
      if (clientSocket > maxSocket) {
        maxSocket = clientSocket;
      }

      cout << LANtable[index].LANaddr << " " << LANtable[index].sockfd << endl;
      //cout << "New connection, socket fd is " << clientSocket << ", IP is : " << inet_ntoa(clientAddress.sin_addr) << ", port : " << ntohs(clientAddress.sin_port) << endl;
    }

    // Check for activity on client sockets
    for (int i = 0; i < clientSockets.size(); ++i) {
      int socketFd = clientSockets[i];

      if (FD_ISSET(socketFd, &tempFds)) {
        // Handle data from the client
        handleClient(socketFd);

        // remove the client socket from the set
        //FD_CLR(socketFd, &readFds);
        //clientSockets.erase(clientSockets.begin() + i);
      }
    }

    index++;
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

      // after getting router's LAN IP, set rLANsubnet to the first 3 bytes of rLANaddr:
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

      NAPTentry napt(LANaddr, LANprt, WANprt);
      table.push_back(napt);
    }
    // get to LAN IP section
    else if (!szLine.empty()) {
      LANentry lan(szLine, 0);
      LANtable.push_back(lan);
    }

    line++;
  }

  // print NAPT table
  for (const auto& entry : table) {
    cout << entry.LANaddr << " " << entry.LANprt << " " << entry.WANprt << endl;
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

uint16_t csum(const void* data, size_t length) {
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

bool vCsum(uint16_t checksum, const void* data, size_t length) {
  uint16_t check = csum(data, length);
  return checksum == check;
}

void rewrite(char* buffer) {
  ip* ipHeader = reinterpret_cast<ip*>(buffer);
  char* pHeader = buffer + ipHeader->ip_hl * 4;
  char* srcIp = inet_ntoa(ipHeader->ip_src);
  char* destIp = inet_ntoa(ipHeader->ip_dst);

  tcphdr* tcpHeader;
  udphdr* udpHeader;
  uint8_t protocol = ipHeader->ip_p;
  uint16_t srcPort;
  if (protocol == IPPROTO_TCP) {
    tcpHeader = reinterpret_cast<tcphdr*>(pHeader);
    srcPort = ntohs(tcpHeader->source);
  } else if (protocol == IPPROTO_UDP) {
    udpHeader = reinterpret_cast<udphdr*>(pHeader);
    srcPort = ntohs(udpHeader->source);
  } 

  int type = getType(srcIp, destIp);
  switch (type) {
    case 0: break; // LAN to LAN, no rewriting
    case 1: { // LAN to WAN
      NAPTentry match = NAPTsearch(table, srcIp, srcPort);
      uint16_t wPort = stoi(match.WANprt);

      // modify source IP in IP header
      strcpy(srcIp, rWANaddr.c_str());

      // modify source port and recalculate checksum in protcol header
      if (protocol == IPPROTO_TCP) {
        tcpHeader->source = htons(wPort);
        int tcpLength = ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 4);
        tcpHeader->check = 0;
        tcpHeader->check = csum(buffer + (ipHeader->ip_hl * 4), tcpLength);
      } else if (protocol == IPPROTO_UDP) {
        udpHeader->source = htons(wPort);
        int udpLength = ntohs(udpHeader->len);
        udpHeader->check = 0;
        udpHeader->check = csum(buffer + (ipHeader->ip_hl * 4), udpLength);
      } 

      // recalculate IP checksum
      ipHeader->ip_sum = 0;
      ipHeader->ip_sum = csum(buffer, ipHeader->ip_hl * 4);
    }
    case 2: { // WAN to LAN

    }
    default: break;
  }
  int length = sizeof(buffer) - 1;
  for (int i = 0; i < length; ++i) {
    cout << hex << setw(2) << setfill('0') << (static_cast<int>(buffer[i]) & 0xFF) << " ";
  }
  cout << dec << endl;

  return;
}

void forward(char* buffer, int bytesRead) {
  ip* ipHeader = reinterpret_cast<ip*>(buffer);
  char* destIp = inet_ntoa(ipHeader->ip_dst);
  --ipHeader->ip_ttl; // decrement ttl field
  ipHeader->ip_sum = 0;
  ipHeader->ip_sum = csum(ipHeader, ipHeader->ip_hl * 4); // recalculate checksum

  char* ipH = reinterpret_cast<char*>(ipHeader);
  memcpy(buffer, ipH, strlen(ipH));

  cout << hex << setfill('0');
  for (size_t i = 0; i < bytesRead; ++i) {
      cout << setw(2) << static_cast<int>(reinterpret_cast<uint8_t*>(buffer)[i]) << " ";
  }
  cout << dec << endl;

  // forward packet
  LANentry forward = LANsearch(LANtable, destIp);
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
    // client disconnected
    //close(clientSocket);
    return;
  }

  buffer[bytesRead] = '\0';

  for (int i = 0; i < bytesRead; ++i) {
    cout << hex << setw(2) << setfill('0') << (static_cast<int>(buffer[i]) & 0xFF) << " ";
  }
  cout << dec << endl;

  rewrite(buffer);
  forward(buffer, bytesRead);

  //close(clientSocket);
}