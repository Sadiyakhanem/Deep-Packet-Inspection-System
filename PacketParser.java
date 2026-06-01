package com.packetanalyzer.parser;

import com.packetanalyzer.model.ParsedPacket;
import com.packetanalyzer.model.RawPacket;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Parses raw PCAP packet bytes into a structured {@link ParsedPacket}.
 * Mirrors the C++ PacketAnalyzer::PacketParser class.
 *
 * <p>Protocol constants are exposed as nested interfaces so callers can
 * reference them symbolically (e.g. {@code Protocol.TCP}).
 */
public class PacketParser {

    // =========================================================================
    // Constants
    // =========================================================================

    public interface EtherType {
        int IPv4 = 0x0800;
        int IPv6 = 0x86DD;
        int ARP  = 0x0806;
    }

    public interface Protocol {
        int ICMP = 1;
        int TCP  = 6;
        int UDP  = 17;
    }

    public interface TCPFlags {
        int FIN = 0x01;
        int SYN = 0x02;
        int RST = 0x04;
        int PSH = 0x08;
        int ACK = 0x10;
        int URG = 0x20;
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Parse a raw packet into {@code parsed}.
     *
     * @return true if parsing succeeded; false if the packet is malformed /
     *         too short.
     */
    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        parsed.timestampSec  = raw.tsSec;
        parsed.timestampUsec = raw.tsUsec;

        byte[] data = raw.data;
        int len = data.length;
        int[] offset = {0};   // boxed so private helpers can advance it

        if (!parseEthernet(data, len, parsed, offset)) return false;

        if (parsed.etherType == EtherType.IPv4) {
            if (!parseIPv4(data, len, parsed, offset)) return false;

            if (parsed.protocol == Protocol.TCP) {
                if (!parseTCP(data, len, parsed, offset)) return false;
            } else if (parsed.protocol == Protocol.UDP) {
                if (!parseUDP(data, len, parsed, offset)) return false;
            }
        }

        // Set payload
        if (offset[0] < len) {
            parsed.payloadLength = len - offset[0];
            parsed.payloadData   = data;
            parsed.payloadOffset = offset[0];
        } else {
            parsed.payloadLength = 0;
            parsed.payloadData   = null;
        }

        return true;
    }

    // =========================================================================
    // Layer parsers
    // =========================================================================

    private static boolean parseEthernet(byte[] data, int len,
                                         ParsedPacket parsed, int[] offset) {
        final int ETH_LEN = 14;
        if (len < ETH_LEN) return false;

        parsed.destMac = macToString(data, 0);
        parsed.srcMac  = macToString(data, 6);
        parsed.etherType = readUint16BE(data, 12);

        offset[0] = ETH_LEN;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len,
                                     ParsedPacket parsed, int[] offset) {
        final int MIN_IP_LEN = 20;
        int base = offset[0];
        if (len < base + MIN_IP_LEN) return false;

        int versionIhl = data[base] & 0xFF;
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;

        if (parsed.ipVersion != 4) return false;

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_LEN || len < base + ipHeaderLen) return false;

        parsed.ttl      = data[base + 8] & 0xFF;
        parsed.protocol = data[base + 9] & 0xFF;
        parsed.srcIp    = ipToString(data, base + 12);
        parsed.destIp   = ipToString(data, base + 16);
        parsed.hasIp    = true;

        offset[0] = base + ipHeaderLen;
        return true;
    }

    private static boolean parseTCP(byte[] data, int len,
                                    ParsedPacket parsed, int[] offset) {
        final int MIN_TCP_LEN = 20;
        int base = offset[0];
        if (len < base + MIN_TCP_LEN) return false;

        parsed.srcPort  = readUint16BE(data, base);
        parsed.destPort = readUint16BE(data, base + 2);
        parsed.seqNumber = readUint32BE(data, base + 4);
        parsed.ackNumber = readUint32BE(data, base + 8);

        int dataOffset = (data[base + 12] & 0xFF) >> 4;
        int tcpHeaderLen = dataOffset * 4;
        parsed.tcpFlags = data[base + 13] & 0xFF;

        if (tcpHeaderLen < MIN_TCP_LEN || len < base + tcpHeaderLen) return false;

        parsed.hasTcp = true;
        offset[0] = base + tcpHeaderLen;
        return true;
    }

    private static boolean parseUDP(byte[] data, int len,
                                    ParsedPacket parsed, int[] offset) {
        final int UDP_LEN = 8;
        int base = offset[0];
        if (len < base + UDP_LEN) return false;

        parsed.srcPort  = readUint16BE(data, base);
        parsed.destPort = readUint16BE(data, base + 2);
        parsed.hasUdp   = true;
        offset[0] = base + UDP_LEN;
        return true;
    }

    // =========================================================================
    // Formatting helpers (public so Main can use them)
    // =========================================================================

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] data, int offset) {
        // Network byte order: first byte is the highest-order octet
        return (data[offset]     & 0xFF) + "." +
               (data[offset + 1] & 0xFF) + "." +
               (data[offset + 2] & 0xFF) + "." +
               (data[offset + 3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case Protocol.ICMP: return "ICMP";
            case Protocol.TCP:  return "TCP";
            case Protocol.UDP:  return "UDP";
            default:            return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCPFlags.SYN) != 0) sb.append("SYN ");
        if ((flags & TCPFlags.ACK) != 0) sb.append("ACK ");
        if ((flags & TCPFlags.FIN) != 0) sb.append("FIN ");
        if ((flags & TCPFlags.RST) != 0) sb.append("RST ");
        if ((flags & TCPFlags.PSH) != 0) sb.append("PSH ");
        if ((flags & TCPFlags.URG) != 0) sb.append("URG ");
        String result = sb.toString().trim();
        return result.isEmpty() ? "none" : result;
    }

    // =========================================================================
    // Byte-reading utilities
    // =========================================================================

    /** Read a big-endian unsigned 16-bit value. */
    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /** Read a big-endian unsigned 32-bit value (returned as long). */
    public static long readUint32BE(byte[] data, int offset) {
        return ((data[offset]     & 0xFFL) << 24) |
               ((data[offset + 1] & 0xFFL) << 16) |
               ((data[offset + 2] & 0xFFL) <<  8) |
                (data[offset + 3] & 0xFFL);
    }
}
