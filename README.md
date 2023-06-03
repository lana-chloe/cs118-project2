# CS118 Project 2

This is the repo for spring23 cs118 project 2.
The Docker environment has the same setting with project 0.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Provided Files

- `project` is the folder to develop codes for future projects.
- `grader` contains an autograder for you to test your program.
- `scenarios` contains test cases and inputs to your program.
- `docker-compose.yaml` and `Dockerfile` are files configuring the containers.

## Docker bash commands

```bash
# Setup the container(s) (make setup)
docker compose up -d

# Bash into the container (make shell)
docker compose exec node1 bash

# Remove container(s) and the Docker image (make clean)
docker compose down -v --rmi all --remove-orphans
```

## Environment

- OS: ubuntu 22.04
- IP: 192.168.10.225. NOT accessible from the host machine.
- Files in this repo are in the `/project` folder. That means, `server.cpp` is `/project/project/server.cpp` in the container.
  - When submission, `server.cpp` should be `project/server.cpp` in the `.zip` file.

## Project 2 specific

### How to use the test script

To test your program with the provided checker, go to the root folder of the repo and
run `python3 grader/executor.py <path-to-server> <path-to-scenario-file>`.  
For example, to run the first given test case, run the following command:
```bash
python3 grader/executor.py project/server scenarios/setting1.json
# Passed check point 1
# Passed check point 2
# OK
```

If your program passes the test, the last line of output will be `OK`.
Otherwise, the first unexpect/missing packet will be printed in hex.
Your program's output to `stdout` and `stderr` will be saved to `stdout.txt` and `stderr.txt`, respectively.
You can use these log files to help you debug your router implementation.
You can also read `executor.py` and modify it (like add extra outputs) to help you.
We will not use the grader in your submitted repo for grading.

### How to write a test scenario

A test scenario is written in a JSON file. There are 5 example test cases in the `scenarios` folder.
The fields of the JSON file are:

- `$schema`: Specify the JSON schema file so your text editor can help you validate the format.
  Should always point to `setting_schema.json`.
- `input`: Specify the input file to the program. Should use relative path to the JSON file.
- `actions`: A list of actions taken in the test scenario. There are 3 types of actions:
  - `send`: Send a TCP/UDP packet at a specified port (`port`).
  - `expect`: Expect to receive a TCP/UDP packet at a specified port (`port`).
  - `check`: Delay for some time for your server to process (`delay`, in seconds).
    Then, check if all expectations are satisfied.
    All packets received since the last checkpoint must be exactly the same as specified in `expect` instructions.
    There should be no unexpected or missing packets
  - The last action of `actions` must be `check`.
- The fields of a packet include:
  - `port`: The ID of the router port to send/receive the packet, not the port number.
  The port numbers are specified in `src_port` and `dst_port`.
  - `src_ip` and `src_port`: The source IP address and port number.
  - `dst_ip` and `dst_port`: The destination IP address and port number.
  - `proto`: The transport layer protocol. Can only be `tcp` or `udp`.
  - `payload`: The application layer payload of the packet. Must be a string.
  - `ttl`: Hop limit of the packet.
  - `seq`: TCP sequence number.
  - `ack`: TCP acknowledge number.
  - `flag`: The flag field in TCP header. Should be specified in numbers. For example, ACK should be `16`.
  - `rwnd`: TCP flow control window.
  - `ip_options_b64`: The IP options. Must be encoded in base64 if specified.
  - `ip_checksum`: The checksum for an IP packet. Automatically computed to be the correct number if not specified.
  - `trans_checksum`: The checksum in the TCP/UDP header. Automatically computed to be the correct number if not specified.
  - Most of these fields are optional, but omitting mandatory fields may crash the grader.

Please read the example JSON files and the schema JSON for details.

### How to examine a test scenario

To print all packets in a test scenario in hex format,
run `python3 grader/packet_generate.py` and input the JSON setting.
You may also use `<` to redirect the input to the JSON file, like
```bash
python3 grader/packet_generate.py < scenarios/setting1.json
# ================== SEND @@ 01 ==================
# 45 00 00 1c 00 00 40 00  40 11 b6 54 c0 a8 01 64 
# c0 a8 01 c8 13 88 17 70  00 08 50 69
# ================== ========== ==================
#
# ================== RECV @@ 02 ==================
# 45 00 00 1c 00 00 40 00  3f 11 b7 54 c0 a8 01 64 
# c0 a8 01 c8 13 88 17 70  00 08 50 69
# ================== ========== ==================
#
# Check point 1
#
# ================== SEND @@ 01 ==================
# 46 00 00 20 00 00 40 00  40 11 b4 4f c0 a8 01 64 
# c0 a8 01 c8 01 01 00 00  13 88 17 70 00 08 50 69
# ================== ========== ==================
#
# ================== RECV @@ 02 ==================
# 46 00 00 20 00 00 40 00  3f 11 b5 4f c0 a8 01 64 
# c0 a8 01 c8 01 01 00 00  13 88 17 70 00 08 50 69
# ================== ========== ==================
#
# Check point 2
#
```

### Other notes

- We will use a different version of grader for the final test to integrate with Gradescope.
  But it will be similar to the given one.
  Modifying the grader in this repo will not affect anything.
- We will include many hidden test cases in the final test. Do not fully depend on the 5 given ones.
  They do not cover all edge cases that we want to test.
- The autograder will only build your program in the `project` folder, and grade the built `server` executable.
  Your program should not depend on other files to run.

## Summary

**Group Members**: Lana Lim (105817312), Samantha Rafter (505577796), Tomas Kaljevic (105535812)

### Specifications

A NAPT router is simulated over TCP connections using BSD socket programming. The program first accepts input to stdin specifying the router’s LAN and WAN IP addresses, the IP addresses of hosts on the network, and a list of static NAPT table entries.

Two vectors are created to track the NAPT configuration and information for forwarding to the correct port over TCP. The NAPT vector contains items mapping an IP address and LAN port to a WAN port. The forwarding table (called LANtable) maps the IP addresses of the WAN port and the local hosts to the corresponding fd for TCP forwarding.

After this setup, a socket is opened to listen on port 5152, and the select() function from the BSD sockets API is used to handle clients in order. A while loop runs indefinitely, and on each iteration, will accept any incoming connections and add the file descriptor to a vector tracking the client sockets. If activity on a socket is detected, the client will be handled.

With client handling, up to 65536 (max. length of an IP packet) bytes are read into a buffer. This buffer is then parsed into an IPv4 header and transport layer (determined by the protocol field of the IP header) header. These are both checked for errors in the checksums, and if TTL < 0, and dropped if either of these is true. If TTL > 0 and the checksums are correct, the buffer is rewritten then forwarded.

Rewriting is handled by again parsing the buffer as an IPv4 header, and first decrementing the TTL field. The type of connection (LAN to LAN/ LAN to WAN/ WAN to LAN) is then found. For LAN to LAN, the checksum is recalculated with the new TTL and the packet is forwarded. For LAN to WAN, if the connection being made is not already in the NAPT table, a new translation is added. The source IP and port are then changed to their WAN counterparts, the IP and transport layer checksums are recalculated, and the packet is forwarded. For WAN to LAN, the packet is dropped if not present in the NAPT table. Otherwise, the destination IP and port are rewritten to the LAN counterparts, the IP and transport checksums are recalculated, and the packet is forwarded. 

Forwarding is achieved by finding the fd corresponding to the packet’s IP address, and then writing the packet to this fd.

### Issues

The main problem faced was in understanding the logic in running IP over TCP. While the IP logic was similar to the way an actual NAPT router would work, knowing where to send information in TCP (since this is a simulation) was more difficult. The solution was found by printing the file descriptors and source IP addresses (parsed from the IPv4 header read into the buffer) every time a connection was made. From interpreting this, we discovered the need for a separate table to map these two variables and the order in which to do so.

### Acknowledgments

* [<netinet/ip.h> source and fields](https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip.h.html)
* [<netinet/tcp.h> source and fields](https://sites.uclouvain.be/SystInfo/usr/include/netinet/tcp.h.html)
* [<netinet/udp.h> source and fields](https://sites.uclouvain.be/SystInfo/usr/include/netinet/udp.h.html)
* [<sys/select.h> man page](https://man7.org/linux/man-pages/man2/select.2.html)
* [Guide to Network Programming Using Sockets checksum calculation](https://beej.us/guide/bgnet0/html/split/project-validating-a-tcp-packet.html#the-tcp-header-checksum)
* [TA Boyan's sample starter code](https://github.com/dboyan/CS118-S23-1A/blob/main/Week%207/select.c)