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
string rLANsubnet;

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
int findEntry(string WANprt) //returns the index of the entry in the table that matches WANprt, -1 otherwise
{
    for (unsigned int i = 0; i < table.size(); i++)
    {
        if (WANprt.compare(table.at(i).WANprt) == 0)
        {
            return i;
        }
    }
    return -1;
}

int findEntry(string LANaddr, string LANprt) //returns the index of the entry in the table that matches (LANaddr, LANprt), -1 otherwise
{
    for (unsigned int i = 0; i < table.size(); i++)
    {
        if (LANprt.compare(table.at(i).LANprt) == 0 && LANaddr.compare(table.at(i).LANaddr) == 0)
        {
            return i;
        }
    }
    return -1;
}

int getType(string sAddr, string dAddr) //Compare src and dest addr to rLANsubnet, return 0 if LAN to LAN, 1 if LAN to WAN, and 2 if WAN to LAN
{ //NOTE: no checking of whether addresses are valid; classify an address as LAN if the 1st three bytes match rLANsubnet, classify as WAN otherwise
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

int main() {
  configureNAPT();

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

  return 0;
}
