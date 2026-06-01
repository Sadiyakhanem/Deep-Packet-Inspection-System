package com.packetanalyzer;

import com.packetanalyzer.dpi.ConnectionTracker;
import com.packetanalyzer.dpi.DpiEngine;
import com.packetanalyzer.model.*;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.reader.PcapReader;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Entry point for the Java Packet Analyzer.
 *
 * Usage:
 *   java -jar packet-analyzer.jar &lt;pcap_file&gt; [max_packets] [--dpi]
 *
 * Arguments:
 *   pcap_file   - Path to a .pcap file
 *   max_packets - (Optional) Maximum number of packets to display; 0 = no limit
 *   --dpi       - (Optional) Enable Deep Packet Inspection / flow tracking
 */
public class Main {

    private static final DateTimeFormatter TS_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0 (Java)");
        System.out.println("====================================");
        System.out.println();

        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        String filename   = args[0];
        int maxPackets    = 0;
        boolean enableDpi = false;

        for (int i = 1; i < args.length; i++) {
            if ("--dpi".equalsIgnoreCase(args[i])) {
                enableDpi = true;
            } else {
                try { maxPackets = Integer.parseInt(args[i]); }
                catch (NumberFormatException e) {
                    System.err.println("Invalid argument: " + args[i]);
                    System.exit(1);
                }
            }
        }

        DpiEngine dpi = enableDpi ? new DpiEngine() : null;

        try (PcapReader reader = new PcapReader()) {
            reader.open(filename);

            System.out.println("\n--- Reading packets ---");

            RawPacket raw       = new RawPacket();
            ParsedPacket parsed = new ParsedPacket();
            int packetCount  = 0;
            int parseErrors  = 0;

            while (reader.readNextPacket(raw)) {
                packetCount++;

                if (PacketParser.parse(raw, parsed)) {
                    printPacketSummary(parsed, packetCount);

                    if (dpi != null) {
                        Connection.Action action = dpi.processPacket(parsed, raw);
                        System.out.printf("  [DPI] Action: %s%n", action);
                    }
                } else {
                    System.err.printf("Warning: Failed to parse packet #%d%n", packetCount);
                    parseErrors++;
                }

                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.printf("%n(Stopped after %d packets)%n", maxPackets);
                    break;
                }
            }

            // Summary
            System.out.println("\n====================================");
            System.out.println("Summary:");
            System.out.printf("  Total packets read:  %d%n", packetCount);
            System.out.printf("  Parse errors:        %d%n", parseErrors);

            if (dpi != null) {
                printDpiSummary(dpi.getTracker());
            }

            System.out.println("====================================");

        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    // =========================================================================
    // Packet pretty-printer
    // =========================================================================

    private static void printPacketSummary(ParsedPacket pkt, int num) {
        System.out.printf("%n========== Packet #%d ==========%n", num);

        // Timestamp
        Instant ts = Instant.ofEpochSecond(pkt.timestampSec, pkt.timestampUsec * 1000L);
        System.out.printf("Time: %s.%06d%n", TS_FMT.format(ts), pkt.timestampUsec);

        // Ethernet
        System.out.println("\n[Ethernet]");
        System.out.printf("  Source MAC:      %s%n", pkt.srcMac);
        System.out.printf("  Destination MAC: %s%n", pkt.destMac);
        String etherDesc = "";
        if      (pkt.etherType == PacketParser.EtherType.IPv4) etherDesc = " (IPv4)";
        else if (pkt.etherType == PacketParser.EtherType.IPv6) etherDesc = " (IPv6)";
        else if (pkt.etherType == PacketParser.EtherType.ARP)  etherDesc = " (ARP)";
        System.out.printf("  EtherType:       0x%04X%s%n", pkt.etherType, etherDesc);

        // IP
        if (pkt.hasIp) {
            System.out.printf("%n[IPv%d]%n", pkt.ipVersion);
            System.out.printf("  Source IP:      %s%n", pkt.srcIp);
            System.out.printf("  Destination IP: %s%n", pkt.destIp);
            System.out.printf("  Protocol:       %s%n", PacketParser.protocolToString(pkt.protocol));
            System.out.printf("  TTL:            %d%n", pkt.ttl);
        }

        // TCP
        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.printf("  Source Port:      %d%n", pkt.srcPort);
            System.out.printf("  Destination Port: %d%n", pkt.destPort);
            System.out.printf("  Sequence Number:  %d%n", pkt.seqNumber);
            System.out.printf("  Ack Number:       %d%n", pkt.ackNumber);
            System.out.printf("  Flags:            %s%n", PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }

        // UDP
        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.printf("  Source Port:      %d%n", pkt.srcPort);
            System.out.printf("  Destination Port: %d%n", pkt.destPort);
        }

        // Payload preview
        if (pkt.payloadLength > 0 && pkt.payloadData != null) {
            System.out.println("\n[Payload]");
            System.out.printf("  Length: %d bytes%n", pkt.payloadLength);
            int previewLen = Math.min(pkt.payloadLength, 32);
            System.out.print("  Preview: ");
            for (int i = 0; i < previewLen; i++) {
                System.out.printf("%02x ", pkt.payloadData[pkt.payloadOffset + i] & 0xFF);
            }
            if (pkt.payloadLength > 32) System.out.print("...");
            System.out.println();
        }
    }

    // =========================================================================
    // DPI summary
    // =========================================================================

    private static void printDpiSummary(ConnectionTracker tracker) {
        System.out.println("\n--- DPI Flow Summary ---");
        ConnectionTracker.TrackerStats stats = tracker.getStats();
        System.out.printf("  Active connections:      %d%n", stats.activeConnections);
        System.out.printf("  Total connections seen:  %d%n", stats.totalConnectionsSeen);
        System.out.printf("  Classified:              %d%n", stats.classifiedConnections);
        System.out.printf("  Blocked:                 %d%n", stats.blockedConnections);

        Map<AppType, Long> dist = new LinkedHashMap<>();
        tracker.forEach(conn -> dist.merge(conn.appType, 1L, Long::sum));

        if (!dist.isEmpty()) {
            System.out.println("\n  Application distribution:");
            dist.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
                .forEach(e -> System.out.printf("    %-15s %d flows%n",
                    e.getKey().displayName(), e.getValue()));
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar packet-analyzer.jar <pcap_file> [max_packets] [--dpi]");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  pcap_file   - Path to a .pcap file captured by Wireshark");
        System.out.println("  max_packets - (Optional) Maximum packets to display (0 = no limit)");
        System.out.println("  --dpi       - (Optional) Enable Deep Packet Inspection");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap 10");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap 0 --dpi");
    }
}
