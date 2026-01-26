# Network Packet Analyzer (Python + Raw Sockets + DPKT)

A lightweight Linux-based packet analyzer built using Python raw sockets and the DPKT library.  
This tool captures Ethernet frames directly from the network interface and decodes IP, TCP, and UDP packets in real time.

---

##  Features

- Captures all incoming/outgoing packets using `AF_PACKET` raw sockets  
- Parses:
  - Ethernet header
  - IP header
  - TCP header
  - UDP header  
- Displays MAC, IP, Ports, Flags, Seq/Ack numbers  
- Timestamp for each packet  
- Error-handling for malformed packets  
- CLI-based real-time monitoring  

---

##  Architecture Overview

1. **Capture Layer**  
   Receives raw frames directly from the NIC using a raw socket.

2. **Parsing Layer**  
   DPKT library decodes the binary data into structured protocol objects.

3. **Output Layer**  
   Packet fields are printed to the terminal.

(Diagrams inside `docs/`)

---

##  Requirements

Python 3.x
dpkt
