package com.packetanalyzer.dpi;

import com.packetanalyzer.model.*;
import com.packetanalyzer.parser.PacketParser;

import java.util.Optional;

/**
 * Deep Packet Inspection engine.
 *
 * Given a parsed packet, the engine:
 * 1. Looks up (or creates) a connection in the tracker.
 * 2. Tries to classify the application via SNI, HTTP Host, or DNS query name.
 * 3. Returns the action that should be taken for this packet.
 *
 * Mirrors the core classification logic from dpi_engine.cpp.
 */
public class DpiEngine {

    private final ConnectionTracker tracker;

    public DpiEngine(int threadId) {
        this.tracker = new ConnectionTracker(threadId);
    }

    public DpiEngine() {
        this(0);
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Process a single packet.
     *
     * @param packet parsed packet (from PacketParser)
     * @param raw    raw packet (provides payload bytes and size)
     * @return action to take (FORWARD, DROP, etc.)
     */
    public Connection.Action processPacket(ParsedPacket packet, RawPacket raw) {
        if (!packet.hasIp) return Connection.Action.FORWARD;

        FiveTuple tuple = buildTuple(packet);
        if (tuple == null) return Connection.Action.FORWARD;

        Connection conn = tracker.getOrCreateConnection(tuple);
        boolean isOutbound = true; // simplified; real impl uses local subnet detection
        tracker.updateConnection(conn, raw.data.length, isOutbound);

        // TCP state machine
        if (packet.hasTcp) updateTcpState(conn, packet.tcpFlags);

        // Classify if not yet done
        if (conn.state != Connection.State.CLASSIFIED && packet.payloadData != null && packet.payloadLength > 0) {
            classify(conn, packet);
        }

        return conn.action;
    }

    public ConnectionTracker getTracker() { return tracker; }

    // =========================================================================
    // Classification
    // =========================================================================

    private void classify(Connection conn, ParsedPacket packet) {
        byte[] payload = packet.payloadData;
        int off = packet.payloadOffset;
        int len = packet.payloadLength;
        if (conn.appType == AppType.YOUTUBE || conn.appType == AppType.FACEBOOK) {
        tracker.blockConnection(conn); 
        return;
    }

        // --- TLS SNI ---
        if (packet.hasTcp && SNIExtractor.isTLSClientHello(payload, off, len)) {
            Optional<String> sni = SNIExtractor.extract(payload, off, len);
            if (sni.isPresent()) {
                AppType app = AppType.fromSni(sni.get());
                tracker.classifyConnection(conn, app, sni.get());
                return;
            }
            // It IS TLS but no SNI extracted
            tracker.classifyConnection(conn, AppType.TLS, "");
            return;
        }

        // --- HTTP Host header ---
        if (packet.hasTcp && packet.srcPort != 443 && packet.destPort != 443) {
            if (SNIExtractor.isHttpRequest(payload, off, len)) {
                Optional<String> host = SNIExtractor.extractHttpHost(payload, off, len);
                if (host.isPresent()) {
                    tracker.classifyConnection(conn, AppType.HTTP, host.get());
                    return;
                }
                tracker.classifyConnection(conn, AppType.HTTP, "");
                return;
            }
        }

        // --- DNS ---
        if (packet.hasUdp && (packet.destPort == 53 || packet.srcPort == 53)) {
            if (SNIExtractor.isDnsQuery(payload, off, len)) {
                Optional<String> query = SNIExtractor.extractDnsQuery(payload, off, len);
                tracker.classifyConnection(conn, AppType.DNS, query.orElse(""));
                return;
            }
        }

        // --- Port-based heuristic fallback ---
        AppType portGuess = guessFromPorts(packet);
        if (portGuess != AppType.UNKNOWN) {
            tracker.classifyConnection(conn, portGuess, "");
        }
    }

    private static AppType guessFromPorts(ParsedPacket p) {
        int lo = Math.min(p.srcPort, p.destPort);
        int hi = Math.max(p.srcPort, p.destPort);
        if (hi == 80  || lo == 80)  return AppType.HTTP;
        if (hi == 443 || lo == 443) return AppType.HTTPS;
        if (hi == 53  || lo == 53)  return AppType.DNS;
        if (hi == 853 || lo == 853) return AppType.TLS; // DNS-over-TLS
        return AppType.UNKNOWN;
    }

    // =========================================================================
    // TCP state tracking
    // =========================================================================

    private static void updateTcpState(Connection conn, int flags) {
        if ((flags & PacketParser.TCPFlags.SYN) != 0 && (flags & PacketParser.TCPFlags.ACK) == 0) {
            conn.synSeen = true;
            conn.state   = Connection.State.NEW;
        } else if ((flags & PacketParser.TCPFlags.SYN) != 0 && (flags & PacketParser.TCPFlags.ACK) != 0) {
            conn.synAckSeen = true;
            conn.state      = Connection.State.ESTABLISHED;
        } else if ((flags & PacketParser.TCPFlags.FIN) != 0) {
            conn.finSeen = true;
            conn.state   = Connection.State.CLOSED;
        } else if ((flags & PacketParser.TCPFlags.RST) != 0) {
            conn.state = Connection.State.CLOSED;
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static FiveTuple buildTuple(ParsedPacket p) {
        if (!p.hasIp) return null;

        // Convert dotted-decimal IP strings back to raw uint32 (network byte order)
        long srcIp = ipStringToLong(p.srcIp);
        long dstIp = ipStringToLong(p.destIp);

        int srcPort = 0, dstPort = 0;
        if (p.hasTcp || p.hasUdp) {
            srcPort = p.srcPort;
            dstPort = p.destPort;
        }

        return new FiveTuple(srcIp, dstIp, srcPort, dstPort, p.protocol);
    }

    static long ipStringToLong(String ip) {
        String[] parts = ip.split("\\.", -1);
        if (parts.length != 4) return 0;
        long v = 0;
        for (int i = 3; i >= 0; i--) {
            v |= (Long.parseLong(parts[i]) & 0xFF) << (i * 8);
        }
        return v;
    }
}
