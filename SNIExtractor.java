package com.packetanalyzer.dpi;

import com.packetanalyzer.parser.PacketParser;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) hostname from a TLS Client Hello.
 * Also detects plain HTTP Host headers and DNS query names.
 *
 * Mirrors the C++ DPI::SNIExtractor / HTTPHostExtractor / DNSExtractor classes.
 *
 * TLS Client Hello wire format (simplified):
 * <pre>
 *   [Record Layer]
 *   0x16           content type = Handshake
 *   2 bytes        TLS version
 *   2 bytes        record length
 *
 *   [Handshake]
 *   0x01           handshake type = Client Hello
 *   3 bytes        length
 *   2 bytes        client version
 *   32 bytes       random
 *   1 byte         session-id length
 *   N bytes        session-id
 *   2 bytes        cipher-suites length
 *   N bytes        cipher suites
 *   1 byte         compression-methods length
 *   N bytes        compression methods
 *   2 bytes        extensions length
 *   [Extensions]
 *     2 bytes        extension type
 *     2 bytes        extension data length
 *     N bytes        extension data
 *     (type 0x0000 = SNI)
 *       2 bytes      SNI list length
 *       1 byte       name type (0x00 = host_name)
 *       2 bytes      name length
 *       N bytes      hostname (ASCII)
 * </pre>
 */
public class SNIExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI          = 0x0000;
    private static final int SNI_TYPE_HOSTNAME      = 0x00;

    // Minimum length needed to even start TLS record + handshake header
    private static final int MIN_TLS_LEN = 5 + 4;

    /**
     * Try to extract an SNI hostname from {@code payload}.
     *
     * @param payload raw TCP payload bytes
     * @param length  number of valid bytes in payload (may be less than payload.length)
     * @return SNI hostname, or empty if not found / not a Client Hello
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTLSClientHello(payload, offset, length)) return Optional.empty();

        try {
            int pos = offset;

            // Skip record-layer header (5 bytes)
            pos += 5;

            // Handshake type (1) + length (3)
            pos += 1 + 3;

            // Client version (2)
            pos += 2;

            // Random (32)
            pos += 32;

            // Session-ID
            if (pos >= offset + length) return Optional.empty();
            int sessionIdLen = payload[pos++] & 0xFF;
            pos += sessionIdLen;

            // Cipher suites
            if (pos + 2 > offset + length) return Optional.empty();
            int cipherLen = PacketParser.readUint16BE(payload, pos); pos += 2;
            pos += cipherLen;

            // Compression methods
            if (pos >= offset + length) return Optional.empty();
            int comprLen = payload[pos++] & 0xFF;
            pos += comprLen;

            // Extensions length
            if (pos + 2 > offset + length) return Optional.empty();
            int extTotalLen = PacketParser.readUint16BE(payload, pos); pos += 2;

            int extEnd = pos + extTotalLen;
            while (pos + 4 <= Math.min(extEnd, offset + length)) {
                int extType = PacketParser.readUint16BE(payload, pos); pos += 2;
                int extLen  = PacketParser.readUint16BE(payload, pos); pos += 2;

                if (extType == EXTENSION_SNI && extLen > 0 && pos + extLen <= offset + length) {
                    // SNI list length (2)
                    int listLen = PacketParser.readUint16BE(payload, pos); pos += 2;
                    if (pos + 3 > offset + length) return Optional.empty();
                    int nameType = payload[pos++] & 0xFF;
                    int nameLen  = PacketParser.readUint16BE(payload, pos); pos += 2;
                    if (nameType == SNI_TYPE_HOSTNAME && pos + nameLen <= offset + length) {
                        return Optional.of(new String(payload, pos, nameLen, StandardCharsets.US_ASCII));
                    }
                    return Optional.empty();
                }
                pos += extLen;
            }
        } catch (ArrayIndexOutOfBoundsException ignored) {
            // Malformed / truncated packet
        }
        return Optional.empty();
    }

    /** Returns true if the payload starts with a valid TLS Client Hello record. */
    public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
        if (length < MIN_TLS_LEN) return false;
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        // TLS version: major must be 3 (SSL 3.0 / TLS 1.x)
        if ((payload[offset + 1] & 0xFF) != 0x03) return false;

        // Handshake type
        if ((payload[offset + 5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;

        return true;
    }

    // =========================================================================
    // HTTP Host header extraction
    // =========================================================================

    /** Extract the HTTP "Host:" header value from a plain-text HTTP request. */
    public static Optional<String> extractHttpHost(byte[] payload, int offset, int length) {
        if (!isHttpRequest(payload, offset, length)) return Optional.empty();
        String text = new String(payload, offset, length, StandardCharsets.ISO_8859_1);
        int idx = text.indexOf("Host:");
        if (idx < 0) idx = text.indexOf("host:");
        if (idx < 0) return Optional.empty();
        int start = idx + 5;
        while (start < text.length() && text.charAt(start) == ' ') start++;
        int end = text.indexOf('\r', start);
        if (end < 0) end = text.indexOf('\n', start);
        if (end < 0) end = text.length();
        return Optional.of(text.substring(start, end).trim());
    }

    /** Returns true if this payload looks like an HTTP request. */
    public static boolean isHttpRequest(byte[] payload, int offset, int length) {
        if (length < 4) return false;
        String start = new String(payload, offset, Math.min(8, length), StandardCharsets.ISO_8859_1);
        return start.startsWith("GET ")   || start.startsWith("POST ") ||
               start.startsWith("HEAD ")  || start.startsWith("PUT ")  ||
               start.startsWith("DELETE") || start.startsWith("CONNECT") ||
               start.startsWith("OPTIONS");
    }

    // =========================================================================
    // DNS query name extraction
    // =========================================================================

    /**
     * Extract the first query name from a DNS request.
     * DNS wire format: 12-byte header, then query sections.
     */
    public static Optional<String> extractDnsQuery(byte[] payload, int offset, int length) {
        if (!isDnsQuery(payload, offset, length)) return Optional.empty();
        try {
            // Header is 12 bytes; question section starts at offset+12
            int pos = offset + 12;
            StringBuilder name = new StringBuilder();
            while (pos < offset + length) {
                int labelLen = payload[pos++] & 0xFF;
                if (labelLen == 0) break;
                if (name.length() > 0) name.append('.');
                if (pos + labelLen > offset + length) return Optional.empty();
                name.append(new String(payload, pos, labelLen, StandardCharsets.US_ASCII));
                pos += labelLen;
            }
            return name.length() > 0 ? Optional.of(name.toString()) : Optional.empty();
        } catch (ArrayIndexOutOfBoundsException e) {
            return Optional.empty();
        }
    }

    /** Returns true if the payload looks like a DNS query (not a response). */
    public static boolean isDnsQuery(byte[] payload, int offset, int length) {
        if (length < 12) return false;
        // QR bit (bit 15 of flags word at offset+2) must be 0 for query
        int flags = PacketParser.readUint16BE(payload, offset + 2);
        return (flags & 0x8000) == 0;
    }
}
