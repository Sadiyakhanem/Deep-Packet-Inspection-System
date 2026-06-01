package com.packetanalyzer.dpi;

import com.packetanalyzer.model.*;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

/**
 * Tracks active network flows in a per-thread flow table.
 * Mirrors the C++ DPI::ConnectionTracker class.
 *
 * <p>Not thread-safe by design — each processing thread should own its own
 * instance (consistent hashing ensures a flow always lands on the same thread).
 */
public class ConnectionTracker {

    private final int fpId;
    private final int maxConnections;
    private final Map<FiveTuple, Connection> connections;

    private long totalSeen       = 0;
    private long classifiedCount = 0;
    private long blockedCount    = 0;

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId           = fpId;
        this.maxConnections = maxConnections;
        this.connections    = new LinkedHashMap<>(maxConnections, 0.75f, true); // access-ordered for LRU
    }

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    // =========================================================================
    // Core operations
    // =========================================================================

    /** Get an existing connection or create a new one. */
    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection c = connections.get(tuple);
        if (c != null) return c;

        if (connections.size() >= maxConnections) evictOldest();

        c = new Connection(tuple);
        connections.put(tuple, c);
        totalSeen++;
        return c;
    }

    /**
     * Get an existing connection (checks both directions).
     * Returns null if no matching connection exists.
     */
    public Connection getConnection(FiveTuple tuple) {
        Connection c = connections.get(tuple);
        if (c != null) return c;
        return connections.get(tuple.reverse());
    }

    /** Update per-flow counters after processing a packet. */
    public void updateConnection(Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.lastSeen = Instant.now();
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    /** Mark a connection as classified with an app type. */
    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        if (conn.state != Connection.State.CLASSIFIED) {
            conn.appType = app;
            conn.sni     = sni != null ? sni : "";
            conn.state   = Connection.State.CLASSIFIED;
            classifiedCount++;
        }
    }

    /** Mark a connection as blocked. */
    public void blockConnection(Connection conn) {
        if (conn == null) return;
        conn.state  = Connection.State.BLOCKED;
        conn.action = Connection.Action.DROP;
        blockedCount++;
    }

    /** Mark a connection as closed and remove it. */
    public void closeConnection(FiveTuple tuple) {
        connections.remove(tuple);
    }

    // =========================================================================
    // Maintenance
    // =========================================================================

    /**
     * Remove connections that have been idle longer than {@code timeout}.
     *
     * @return number of connections removed
     */
    public int cleanupStale(Duration timeout) {
        Instant cutoff = Instant.now().minus(timeout);
        int removed = 0;
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().lastSeen.isBefore(cutoff)) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    public int cleanupStale() {
        return cleanupStale(Duration.ofSeconds(300));
    }

    /** Clear all connections. */
    public void clear() {
        connections.clear();
    }

    // =========================================================================
    // Reporting
    // =========================================================================

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public void forEach(Consumer<Connection> action) {
        connections.values().forEach(action);
    }

    public static class TrackerStats {
        public final long activeConnections;
        public final long totalConnectionsSeen;
        public final long classifiedConnections;
        public final long blockedConnections;

        TrackerStats(long active, long total, long classified, long blocked) {
            this.activeConnections      = active;
            this.totalConnectionsSeen   = total;
            this.classifiedConnections  = classified;
            this.blockedConnections     = blocked;
        }
    }

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /** Evict the least-recently-used connection (LinkedHashMap access-order). */
    private void evictOldest() {
        Iterator<FiveTuple> it = connections.keySet().iterator();
        if (it.hasNext()) {
            it.next();
            it.remove();
        }
    }
}
