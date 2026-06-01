package com.packetanalyzer.reader;

import com.packetanalyzer.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads packets from a PCAP file.
 * Mirrors the C++ PacketAnalyzer::PcapReader class.
 */
public class PcapReader implements Closeable {

    // Both constants expressed as the raw little-endian uint32 value stored in file bytes.
    // 0xA1B2C3D4 = native (file is little-endian); 0xD4C3B2A1 = swapped (file is big-endian).
    private static final long PCAP_MAGIC_LE = 0xA1B2C3D4L; // native LE file
    private static final long PCAP_MAGIC_BE = 0xD4C3B2A1L; // native BE file

    private DataInputStream in;
    private boolean needsByteSwap;

    public int  versionMajor;
    public int  versionMinor;
    public long snaplen;
    public long network;

    public void open(String filename) throws IOException {
        FileInputStream fis = new FileInputStream(filename);
        in = new DataInputStream(new BufferedInputStream(fis));
        readGlobalHeader(filename);
    }

    private void readGlobalHeader(String filename) throws IOException {
        byte[] hdr = new byte[24];
        readFully(hdr, 0, 24);

        // Read the 4-byte magic field as a raw little-endian uint32
        // (just assembling the 4 bytes without imposing any byte order).
        long magic = ((hdr[0] & 0xFFL))       |
                     ((hdr[1] & 0xFFL) <<  8)  |
                     ((hdr[2] & 0xFFL) << 16)  |
                     ((hdr[3] & 0xFFL) << 24);

        if (magic == PCAP_MAGIC_LE) {
            needsByteSwap = false;   // file is little-endian, same as x86
        } else if (magic == PCAP_MAGIC_BE) {
            needsByteSwap = true;    // file is big-endian, must swap
        } else {
            throw new IOException(String.format(
                "Invalid PCAP magic number: 0x%08X in file: %s", magic, filename));
        }

        // Parse the rest of the global header with the correct byte order
        ByteBuffer buf = ByteBuffer.wrap(hdr);
        buf.order(needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

        buf.getInt();  // magic already read
        versionMajor = buf.getShort() & 0xFFFF;
        versionMinor = buf.getShort() & 0xFFFF;
        buf.getInt();  // thiszone
        buf.getInt();  // sigfigs
        snaplen = buf.getInt() & 0xFFFFFFFFL;
        network = buf.getInt() & 0xFFFFFFFFL;

        System.out.println("Opened PCAP file: " + filename);
        System.out.printf("  Version: %d.%d%n", versionMajor, versionMinor);
        System.out.printf("  Snaplen: %d bytes%n", snaplen);
        System.out.printf("  Link type: %d%s%n", network, network == 1 ? " (Ethernet)" : "");
    }

    public boolean readNextPacket(RawPacket packet) throws IOException {
        byte[] phdr = new byte[16];
        int read = tryReadFully(phdr, 0, 16);
        if (read == 0) return false;
        if (read < 16) throw new IOException("Truncated packet header");

        ByteBuffer buf = ByteBuffer.wrap(phdr);
        buf.order(needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

        packet.tsSec   = buf.getInt() & 0xFFFFFFFFL;
        packet.tsUsec  = buf.getInt() & 0xFFFFFFFFL;
        packet.inclLen = buf.getInt() & 0xFFFFFFFFL;
        packet.origLen = buf.getInt() & 0xFFFFFFFFL;

        if (packet.inclLen > Math.max(snaplen, 65535L) || packet.inclLen > 65535) {
            throw new IOException("Invalid packet length: " + packet.inclLen);
        }

        packet.data = new byte[(int) packet.inclLen];
        readFully(packet.data, 0, (int) packet.inclLen);
        return true;
    }

    @Override
    public void close() throws IOException {
        if (in != null) { in.close(); in = null; }
    }

    private void readFully(byte[] buf, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int n = in.read(buf, off + total, len - total);
            if (n < 0) throw new EOFException("Unexpected end of PCAP data");
            total += n;
        }
    }

    private int tryReadFully(byte[] buf, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int n = in.read(buf, off + total, len - total);
            if (n < 0) return total;
            total += n;
        }
        return total;
    }
}
