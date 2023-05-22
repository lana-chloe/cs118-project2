#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
using namespace std;

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
  int lineNumber = 1;

  while (getline(cin, szLine)) {
      // first line is the router's LAN IP and the WAN IP
      if (lineNumber == 1) {
        size_t dwPos = szLine.find(' ');
        rLANaddr = szLine.substr(0, dwPos);
        rWANaddr = szLine.substr(dwPos + 1);
        cout << "rLANaddr: " << rLANaddr << endl;
        cout << "rWANaddr: " << rWANaddr << endl;
      }
      // get to NAPT table section
      else if (szLine.find(' ') != string::npos) {
        size_t first = szLine.find(' '); // first space char
        size_t second = szLine.find(' ', first + 1); // second space char
    
        // extract three substrings
        string LANaddr = szLine.substr(0, first);
        string LANprt = szLine.substr(first + 1, second - first - 1);
        string WANprt = szLine.substr(second + 1);

        cout << "LANaddr: " << LANaddr << endl;
        cout << "LANprt: " << LANprt << endl;
        cout << "WANprt: " << WANprt << endl;

        // add to NAPT table
        NAPTEntry entry(LANaddr, LANprt, WANprt);
        table.push_back(entry);
      }

      lineNumber++;
  }
}

int main() {
  configureNAPT();
  return 0;
}
