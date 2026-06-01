# Java Packet Analyzer

A Java-based network traffic analysis tool that reads `.pcap` files, decodes packets across multiple network layers, reconstructs communication flows, and performs Deep Packet Inspection (DPI) to identify application-level traffic such as Google, YouTube, Netflix, WhatsApp, GitHub, and more.

## Overview

Network communication occurs through packets that travel across different layers of the TCP/IP stack. Understanding these packets is essential for network monitoring, troubleshooting, traffic analysis, and cybersecurity.

This project analyzes offline packet captures (`.pcap` files) by parsing packet headers, extracting protocol information, tracking network flows, and classifying traffic using DPI techniques.

Unlike traditional packet analyzers that depend on native libraries such as libpcap, this implementation is written entirely in Java, making it platform-independent and easy to run on any system with Java installed.

---

## Features

### Packet Parsing

* Reads and processes standard `.pcap` files
* Parses Ethernet frames
* Decodes IPv4 packets
* Extracts TCP and UDP header information
* Displays packet metadata in a human-readable format

### Flow Tracking

* Reconstructs network conversations

* Uses Five-Tuple identification:

  * Source IP Address
  * Destination IP Address
  * Source Port
  * Destination Port
  * Protocol

* Tracks:

  * Packet count
  * Byte count
  * Flow duration
  * Activity timestamps

### Deep Packet Inspection (DPI)

Traffic classification is performed using multiple techniques:

#### TLS SNI Analysis

Extracts hostnames from TLS Client Hello packets.

Example:

```text
www.youtube.com
```

#### HTTP Host Header Inspection

Extracts domains from HTTP requests.

Example:

```http
Host: github.com
```

#### DNS Query Inspection

Parses DNS traffic to identify requested domains.

Example:

```text
api.whatsapp.com
```

#### Port-Based Classification

Fallback classification using well-known ports.

| Port | Service |
| ---- | ------- |
| 80   | HTTP    |
| 443  | HTTPS   |
| 53   | DNS     |
| 22   | SSH     |

---

## Supported Protocols

### Link Layer

* Ethernet

### Network Layer

* IPv4

### Transport Layer

* TCP
* UDP

### Application Detection

The analyzer can identify traffic related to:

* Google
* YouTube
* Facebook
* Instagram
* WhatsApp
* Netflix
* Telegram
* Discord
* Spotify
* GitHub
* Zoom
* TikTok
* Cloudflare
* Amazon AWS
* Microsoft Azure
* Apple iCloud
* Generic HTTP / HTTPS / DNS Traffic

---

## System Architecture

```text
                 +------------------+
                 |     Main.java    |
                 +---------+--------+
                           |
                           v
                 +------------------+
                 |    PcapReader    |
                 +---------+--------+
                           |
                           v
                 +------------------+
                 |  PacketParser    |
                 +---------+--------+
                           |
          +----------------+----------------+
          |                                 |
          v                                 v
 +------------------+             +------------------+
 |  ParsedPacket    |             |    DpiEngine     |
 +------------------+             +---------+--------+
                                            |
                                            v
                                  +------------------+
                                  | ConnectionTracker|
                                  +------------------+
```

---

## Project Structure

```text
src/main/java/com/packetanalyzer/

├── Main.java
│
├── model/
│   ├── RawPacket.java
│   ├── ParsedPacket.java
│   ├── FiveTuple.java
│   ├── Connection.java
│   └── AppType.java
│
├── reader/
│   └── PcapReader.java
│
├── parser/
│   └── PacketParser.java
│
└── dpi/
    ├── DpiEngine.java
    ├── ConnectionTracker.java
    └── SNIExtractor.java
```

---

## Core Components

### PcapReader

Responsible for:

* Reading PCAP global headers
* Detecting byte order
* Extracting raw packet data
* Creating packet objects

### PacketParser

Responsible for:

* Ethernet parsing
* IPv4 parsing
* TCP parsing
* UDP parsing
* Payload extraction

### ConnectionTracker

Maintains active network flows using Five-Tuple identifiers and updates flow statistics for every packet processed.

### DpiEngine

Performs traffic classification using:

1. TLS SNI inspection
2. HTTP Host inspection
3. DNS query analysis
4. Port heuristics

### SNIExtractor

Extracts:

* TLS Server Name Indication (SNI)
* HTTP Host headers
* DNS domain names

---

## Technologies Used

| Technology       | Purpose               |
| ---------------- | --------------------- |
| Java 11+         | Core Development      |
| Maven            | Build Automation      |
| ByteBuffer       | Binary Packet Parsing |
| Java Collections | Flow Management       |
| OOP Principles   | System Design         |

---

## Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/java-packet-analyzer.git
cd java-packet-analyzer
```

### Build Project

```bash
mvn clean package
```

---

## Running the Application

### Basic Analysis

```bash
java -jar packet-analyzer.jar traffic.pcap
```

### Analyze Limited Packets

```bash
java -jar packet-analyzer.jar traffic.pcap 100
```

### Enable Deep Packet Inspection

```bash
java -jar packet-analyzer.jar traffic.pcap 0 --dpi
```

---

## Sample Output

```text
====================================
Packet Analyzer
====================================

Packet #1

Source IP:      192.168.1.100
Destination IP: 142.250.185.206

Protocol: TCP
Source Port: 54552
Destination Port: 443

[DPI] Application: Google
```

---

## Challenges Solved

* Parsing binary packet structures in Java
* Handling different PCAP byte-order formats
* Reconstructing network flows efficiently
* Extracting TLS SNI information without external libraries
* Designing a modular DPI classification engine
* Managing flow state and statistics at scale

---

## Learning Outcomes

This project provided hands-on experience with:

* Computer Networking
* TCP/IP Protocol Stack
* Packet Analysis
* Deep Packet Inspection (DPI)
* Network Flow Reconstruction
* Binary Data Processing
* Java Collections Framework
* Object-Oriented System Design

---

## Future Enhancements

* IPv6 Support
* PCAPNG Support
* Live Packet Capture
* GUI Dashboard
* Traffic Visualization
* Export Reports (JSON / CSV)
* Advanced DPI Signatures
* Real-Time Monitoring

---

