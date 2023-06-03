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

  NAPTentry() : LANaddr(""), LANprt(""), WANprt("") {}

  NAPTentry(string Laddr, string Lprt, string Wprt)
    : LANaddr(Laddr), LANprt(Lprt), WANprt(Wprt) {}
};

// LAN IPs table entry 
struct LANentry {
  string LANaddr;
  int sockfd;

  LANentry () : LANaddr(""), sockfd(0) {}

  LANentry(string Laddr, int sfd) 
    : LANaddr(Laddr), sockfd(sfd) {}
};

// tables
vector<NAPTentry> table;
vector<LANentry> LANtable;

// original router LAN and WAN addresses
string rLANaddr;
string rWANaddr;
string rLANsubnet;

//////////////////////
// STRUCT FUNCTIONS //
//////////////////////
LANentry LANsearch(string Laddr) {
  for (const auto& item : LANtable) {
    if (item.LANaddr == Laddr) {
      return item;
    }
  }
  return LANentry(); // default struct
}

NAPTentry searchLW(string Laddr, int Lprt) {
  string LANprt = to_string(Lprt);
  for (const auto& item : table) {
    if (item.LANaddr == Laddr && item.LANprt == LANprt) {
      return item;
    }
  }
  return NAPTentry(); // default struct
}

NAPTentry searchWL(int Wprt) {
  string WANprt = to_string(Wprt);
  for (const auto& item : table) {
    if (item.WANprt == WANprt) {
      return item;
    }
  }
  return NAPTentry(); // default struct
}

///////////////////////////
// FUNCTION DECLARATIONS //
///////////////////////////
// tables
void configureNAPT(); 
int findEntry(string WANprt); // returns the index of the entry in the table that matches WANprt, -1 otherwise 
int findEntry(string LANaddr, string LANprt); // returns the index of the entry in the table that matches (LANaddr, LANprt), -1 otherwise
int getType(string sAddr, string dAddr); // compare src and dest addr to rLANsubnet, return 0 if LAN to LAN, 1 if LAN to WAN, and 2 if WAN to LAN

// checksum
uint16_t csum(const void* data, size_t length); // calculate IP checksum
uint16_t cTsum(const ip* ipHeader, const tcphdr* tcpHeader, const char* payload, size_t payloadLength); // calculate TCP checksum
uint16_t cUsum(const ip* ipHeader, const udphdr* udpHeader, const char* payload, size_t payloadLength); // calculate UDP checksum

// rewriting and forwarding
void rewrite(char* buffer); 
void forward(char* buffer, int bytesRead); 
void handleClient(int clientSocket); 

////////////////////
// IMPLEMENTATION //
////////////////////
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
      string WANprt = szLine.substr(second + 1, end - second - 1);

      NAPTentry entry(LANaddr, LANprt, WANprt);
      table.push_back(entry);
    }
    // get to LAN IP section
    else if (!szLine.empty()) {
      LANentry entry(szLine, 0);
      LANtable.push_back(entry);
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
  else if ((src == 1 && dst == 0) || sAddr == rWANaddr) //LAN to WAN
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

uint16_t cTsum(const ip* ipHeader, const tcphdr* tcpHeader, const char* payload, size_t payloadLength) {
  uint32_t sum = 0;

  // pseudo-header for checksum calculation
  struct pseudo_header {
      uint32_t sourceIp;
      uint32_t destIp;
      uint8_t placeholder;
      uint8_t protocol;
      uint16_t tcpLength;
  } pseudoHeader;

  pseudoHeader.sourceIp = ipHeader->ip_src.s_addr;
  pseudoHeader.destIp = ipHeader->ip_dst.s_addr;
  pseudoHeader.placeholder = 0;
  pseudoHeader.protocol = IPPROTO_TCP;
  pseudoHeader.tcpLength = htons(sizeof(tcphdr) + payloadLength);

  // calculate the checksum over the pseudo-header
  const uint16_t* pseudoBuf = reinterpret_cast<const uint16_t*>(&pseudoHeader);
  size_t pseudoLength = sizeof(pseudo_header);
  while (pseudoLength > 1) {
      sum += *pseudoBuf;
      pseudoBuf++;
      pseudoLength -= 2;
  }

  // calculate the checksum over the TCP header and payload
  const uint16_t* tcpBuf = reinterpret_cast<const uint16_t*>(tcpHeader);
  size_t tcpLength = sizeof(tcphdr) + payloadLength;
  while (tcpLength > 1) {
      sum += *tcpBuf;
      tcpBuf++;
      tcpLength -= 2;
  }

  // case of odd-length TCP packet
  if (tcpLength == 1) {
      sum += *reinterpret_cast<const uint8_t*>(tcpBuf);
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

uint16_t cUsum(const ip* ipHeader, const udphdr* udpHeader, const char* payload, size_t payloadLength) {
  uint32_t sum = 0;

  // pseudo-header for checksum calculation
  struct pseudo_header {
      uint32_t sourceIp;
      uint32_t destIp;
      uint8_t placeholder;
      uint8_t protocol;
      uint16_t udpLength;
  } pseudoHeader;

  pseudoHeader.sourceIp = ipHeader->ip_src.s_addr;
  pseudoHeader.destIp = ipHeader->ip_dst.s_addr;
  pseudoHeader.placeholder = 0;
  pseudoHeader.protocol = IPPROTO_UDP;
  pseudoHeader.udpLength = htons(sizeof(udphdr) + payloadLength);

  // calculate the checksum over the pseudo-header
  const uint16_t* pseudoBuf = reinterpret_cast<const uint16_t*>(&pseudoHeader);
  size_t pseudoLength = sizeof(pseudo_header);
  while (pseudoLength > 1) {
      sum += *pseudoBuf;
      pseudoBuf++;
      pseudoLength -= 2;
  }

  // calculate the checksum over the UDP header and payload
  const uint16_t* udpBuf = reinterpret_cast<const uint16_t*>(udpHeader);
  size_t udpLength = sizeof(udphdr) + payloadLength;
  while (udpLength > 1) {
      sum += *udpBuf;
      udpBuf++;
      udpLength -= 2;
  }

  // case of odd-length UDP packet
  if (udpLength == 1) {
      sum += *reinterpret_cast<const uint8_t*>(udpBuf);
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

void rewrite(char* buffer) {
  ip* ipHeader = reinterpret_cast<ip*>(buffer);

  cout << "IP header: " << endl;
  char* tmp = reinterpret_cast<char*>(ipHeader);
  for (int i = 0; i < sizeof(ip); ++i) {
    cout << hex << setw(2) << setfill('0') << (static_cast<int>(tmp[i]) & 0xFF) << " ";
  }
  cout << dec << endl;


  char* pHeader = buffer + ipHeader->ip_hl * 4;
  string srcIp = inet_ntoa(ipHeader->ip_src);
  string destIp = inet_ntoa(ipHeader->ip_dst);
  uint8_t protocol = ipHeader->ip_p;
  tcphdr* tcpHeader;
  udphdr* udpHeader;
  uint16_t srcPort;
  uint16_t destPort;

  if (protocol == IPPROTO_TCP) {
    tcpHeader = reinterpret_cast<tcphdr*>(pHeader);
    srcPort = ntohs(tcpHeader->source);
    destPort = ntohs(tcpHeader->th_dport);
  } else if (protocol == IPPROTO_UDP) {
    udpHeader = reinterpret_cast<udphdr*>(pHeader);
    srcPort = ntohs(udpHeader->source);
    destPort = ntohs(udpHeader->uh_dport);
  } 

  int type = getType(srcIp, destIp);
  switch (type) {
    case 0: return; // LAN to LAN, no rewriting
    case 1: { // LAN to WAN
      // find LAN to WAN translation
      NAPTentry match = searchLW(srcIp, srcPort);
      uint16_t wPort = stoi(match.WANprt);

      // modify source IP
      inet_pton(AF_INET, rWANaddr.c_str(), &(ipHeader->ip_src));

      // modify source port and recalculate protcol checksum
      if (protocol == IPPROTO_TCP) {
        tcpHeader->source = htons(wPort);
        tcpHeader->check = 0;
        tcpHeader->check = cTsum(ipHeader, tcpHeader, buffer + ipHeader->ip_hl * 4 + sizeof(tcphdr), ntohs(ipHeader->ip_len) - ipHeader->ip_hl * 4 - sizeof(tcphdr));
      } else if (protocol == IPPROTO_UDP) {
        udpHeader->source = htons(wPort);
        udpHeader->check = 0;
        udpHeader->check = cUsum(ipHeader, udpHeader, buffer + ipHeader->ip_hl * 4 + sizeof(udphdr), ntohs(udpHeader->len) - sizeof(udphdr));
      } 

      // recalculate IP checksum
      ipHeader->ip_sum = 0;
      ipHeader->ip_sum = csum(ipHeader, ipHeader->ip_hl * 4);

      break;
    }
    case 2: { // WAN to LAN
      // STATIC NAPT
      NAPTentry match = searchWL(destPort);
      string dIp = match.LANaddr;
      uint16_t dP = stoi(match.LANprt);

      // modify dest IP
      inet_pton(AF_INET, dIp.c_str(), &(ipHeader->ip_dst));

      // modify dest port and recalculate protcol checksum
      if (protocol == IPPROTO_TCP) {
        tcpHeader->th_dport = htons(dP);
        tcpHeader->check = 0;
        tcpHeader->check = cTsum(ipHeader, tcpHeader, buffer + ipHeader->ip_hl * 4 + sizeof(tcphdr), ntohs(ipHeader->ip_len) - ipHeader->ip_hl * 4 - sizeof(tcphdr));
        cout << ntohs(tcpHeader->source) << " " << ntohs(tcpHeader->th_dport) << endl;
        
        cout << "TCP header: " << endl;
        char* tmp = reinterpret_cast<char*>(tcpHeader);
        for (int i = 0; i < sizeof(tcphdr); ++i) {
          cout << hex << setw(2) << setfill('0') << (static_cast<int>(tmp[i]) & 0xFF) << " ";
        }
        cout << dec << endl;

        cout << "TCP header + payload: " << endl;
        tmp = buffer + ipHeader->ip_hl * 4;
         for (int i = 0; i < (ntohs(ipHeader->ip_len) - ipHeader->ip_hl * 4); ++i) {
          cout << hex << setw(2) << setfill('0') << (static_cast<int>(tmp[i]) & 0xFF) << " ";
        }
        cout << dec << endl;

      } else if (protocol == IPPROTO_UDP) {
        udpHeader->uh_dport = htons(dP);
        udpHeader->check = 0;
        udpHeader->check = cUsum(ipHeader, udpHeader, buffer + ipHeader->ip_hl * 4 + sizeof(udphdr), ntohs(udpHeader->len) - sizeof(udphdr));
        cout << ntohs(udpHeader->source) << " " << ntohs(udpHeader->uh_dport) << endl;
      } 

      // recalculate IP checksum
      ipHeader->ip_sum = 0;
      ipHeader->ip_sum = csum(ipHeader, ipHeader->ip_hl * 4);

      cout << inet_ntoa(ipHeader->ip_src) << " " << inet_ntoa(ipHeader->ip_dst) << " " << endl;

      break;
    }
    default: break;
  }

  for (int i = 0; i < strlen(buffer); ++i) {
    cout << hex << setw(2) << setfill('0') << (static_cast<int>(buffer[i]) & 0xFF) << " ";
  }
  cout << dec << endl;

  return;
}

void forward(char* buffer, int bytesRead) {
  ip* ipHeader = reinterpret_cast<ip*>(buffer);
  string srcIp = inet_ntoa(ipHeader->ip_src);
  string destIp = inet_ntoa(ipHeader->ip_dst);
  
  --ipHeader->ip_ttl; // decrement ttl field
  ipHeader->ip_sum = 0;
  ipHeader->ip_sum = csum(ipHeader, ipHeader->ip_hl * 4); // recalculate checksum

  cout << "Packet being sent:" << endl;
  cout << hex << setfill('0');
  for (size_t i = 0; i < bytesRead; ++i) {
      cout << setw(2) << static_cast<int>(reinterpret_cast<uint8_t*>(buffer)[i]) << " ";
  }
  cout << dec << endl << endl;

  // forward packet
  int type = getType(srcIp, destIp);
  cout << "Type: " << type << endl;
  switch (type) {
    case 2: // WAN to LAN
    case 0: { // LAN to LAN
      LANentry forward = LANsearch(destIp);
      send(forward.sockfd, buffer, bytesRead, 0);
      break;
    }
    case 1: { // LAN to WAN
      LANentry forward = LANtable[0];
      send(forward.sockfd, buffer, bytesRead, 0);
      break;
    }
    default: break;
  }
}

void handleClient(int clientSocket) {
  char buffer[BUF_SIZE];
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

  cout << "Before rewrite:" << endl;
  for (int i = 0; i < bytesRead; ++i) {
    cout << hex << setw(2) << setfill('0') << (static_cast<int>(buffer[i]) & 0xFF) << " ";
  }
  cout << dec << endl;

  rewrite(buffer);

  cout << "After rewrite:" << endl;
  for (int i = 0; i < bytesRead; ++i) {
    cout << hex << setw(2) << setfill('0') << (static_cast<int>(buffer[i]) & 0xFF) << " ";
  }
  cout << dec << endl;

  forward(buffer, bytesRead);

  //close(clientSocket);
}