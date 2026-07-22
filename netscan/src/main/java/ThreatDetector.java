import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ThreatDetector {

    // ── Thresholds ────────────────────────────────────────────────────────
    private static final int    SYN_FLOOD_THRESHOLD   = 20;  // SYNs per 5s window
    private static final int    PORT_SCAN_THRESHOLD   = 15;  // unique dest ports per IP
    private static final int    HIGH_TRAFFIC_THRESHOLD = 500; // packets per 5s window
    private static final double ANOMALY_SCORE_THRESHOLD = -0.3; // from Isolation Forest

    // ── Per-IP port tracking (for port scan detection) ────────────────────
    // Map: sourceIp → Set of destination ports seen
    private final Map<String, Set<Integer>> ipToDestPorts = new ConcurrentHashMap<>();

    // ── Per-IP SYN tracking ───────────────────────────────────────────────
    // Map: sourceIp → SYN count in current window
    private final Map<String, Integer> ipToSynCount = new ConcurrentHashMap<>();

    // ── Alert history — avoid spamming same alert repeatedly ──────────────
    private final Set<String> recentAlerts = ConcurrentHashMap.newKeySet();

    // ── Lifetime counters ─────────────────────────────────────────────────
    private int totalThreatsDetected = 0;

    // ── Called for every captured packet ─────────────────────────────────
    public void analyze(PacketInfo packet) {

        String srcIp  = packet.getSourceIp();
        int    dstPort = packet.getDestPort();

        // Track destination ports per source IP
        if (dstPort != -1) {
            ipToDestPorts
                .computeIfAbsent(srcIp, k -> ConcurrentHashMap.newKeySet())
                .add(dstPort);
        }

        // Track SYN packets per source IP
        if (packet.getTcpFlags().contains("SYN")
                && !packet.getTcpFlags().contains("ACK")) {
            ipToSynCount.merge(srcIp, 1, Integer::sum);
        }
    }

    // ── Called every 5s from PacketStats ─────────────────────────────────
    public List<ThreatAlert> evaluate(
            int    totalPacketsInWindow,
            int    synCountInWindow,
            int    uniquePortsInWindow,
            double anomalyScore) {

        List<ThreatAlert> alerts = new ArrayList<>();

        // ── Check 1: Global SYN flood ─────────────────────────────────────
        if (synCountInWindow >= SYN_FLOOD_THRESHOLD) {
            String key = "SYN_FLOOD_GLOBAL";
            if (!recentAlerts.contains(key)) {
                alerts.add(new ThreatAlert(
                    ThreatType.SYN_FLOOD,
                    "GLOBAL",
                    String.format(
                        "SYN flood detected — %d SYN packets in 5s window (threshold: %d)",
                        synCountInWindow, SYN_FLOOD_THRESHOLD),
                    Severity.HIGH
                ));
                recentAlerts.add(key);
            }
        } else {
            recentAlerts.remove("SYN_FLOOD_GLOBAL"); // reset when traffic normalizes
        }

        // ── Check 2: Per-IP SYN flood ─────────────────────────────────────
        for (Map.Entry<String, Integer> entry : ipToSynCount.entrySet()) {
            String ip       = entry.getKey();
            int    synCount = entry.getValue();

            if (synCount >= SYN_FLOOD_THRESHOLD / 2) { // stricter per-IP threshold
                String key = "SYN_FLOOD_" + ip;
                if (!recentAlerts.contains(key)) {
                    alerts.add(new ThreatAlert(
                        ThreatType.SYN_FLOOD,
                        ip,
                        String.format(
                            "SYN flood from %s — %d SYN packets (threshold: %d)",
                            ip, synCount, SYN_FLOOD_THRESHOLD / 2),
                        Severity.HIGH
                    ));
                    recentAlerts.add(key);
                }
            } else {
                recentAlerts.remove("SYN_FLOOD_" + ip);
            }
        }

        // ── Check 3: Per-IP port scan ─────────────────────────────────────
        for (Map.Entry<String, Set<Integer>> entry : ipToDestPorts.entrySet()) {
            String      ip    = entry.getKey();
            Set<Integer> ports = entry.getValue();

            if (ports.size() >= PORT_SCAN_THRESHOLD) {
                String key = "PORT_SCAN_" + ip;
                if (!recentAlerts.contains(key)) {
                    alerts.add(new ThreatAlert(
                        ThreatType.PORT_SCAN,
                        ip,
                        String.format(
                            "Port scan from %s — hitting %d unique ports: %s...",
                            ip, ports.size(), firstN(ports, 5)),
                        Severity.MEDIUM
                    ));
                    recentAlerts.add(key);
                }
            } else {
                recentAlerts.remove("PORT_SCAN_" + ip);
            }
        }

        // ── Check 4: High traffic volume ──────────────────────────────────
        if (totalPacketsInWindow >= HIGH_TRAFFIC_THRESHOLD) {
            String key = "HIGH_TRAFFIC";
            if (!recentAlerts.contains(key)) {
                alerts.add(new ThreatAlert(
                    ThreatType.HIGH_TRAFFIC,
                    "GLOBAL",
                    String.format(
                        "High traffic volume — %d packets in 5s (threshold: %d)",
                        totalPacketsInWindow, HIGH_TRAFFIC_THRESHOLD),
                    Severity.LOW
                ));
                recentAlerts.add(key);
            }
        } else {
            recentAlerts.remove("HIGH_TRAFFIC");
        }

        // ── Check 5: ML anomaly score correlation ─────────────────────────
        if (anomalyScore <= ANOMALY_SCORE_THRESHOLD) {
            String key = "ML_ANOMALY";
            if (!recentAlerts.contains(key)) {
                alerts.add(new ThreatAlert(
                    ThreatType.ML_ANOMALY,
                    "GLOBAL",
                    String.format(
                        "ML model flagged anomalous traffic — score: %.4f (threshold: %.1f)",
                        anomalyScore, ANOMALY_SCORE_THRESHOLD),
                    Severity.HIGH
                ));
                recentAlerts.add(key);
            }
        } else {
            recentAlerts.remove("ML_ANOMALY");
        }

        totalThreatsDetected += alerts.size();
        return alerts;
    }

    // ── Reset per-window counters (call after each 5s window) ─────────────
    public void resetWindow() {
        ipToSynCount.clear();
        ipToDestPorts.clear();
        recentAlerts.clear(); // allow re-alerting next window
    }

    // ── Summary ───────────────────────────────────────────────────────────
    public void printSummary() {
        System.out.println("\n── ThreatDetector Summary ───────────────────────");
        System.out.printf("  %-25s %d%n", "Total threats detected:", totalThreatsDetected);
        System.out.println("─".repeat(50));
    }

    // ── Helper: first N items from a set as string ────────────────────────
    private String firstN(Set<Integer> set, int n) {
        StringBuilder sb = new StringBuilder("[");
        int count = 0;
        for (int val : set) {
            if (count++ >= n) { sb.append("..."); break; }
            sb.append(val).append(count < Math.min(n, set.size()) ? ", " : "");
        }
        return sb.append("]").toString();
    }

    // ─────────────────────────────────────────────────────────────────────
    // ThreatType enum
    // ─────────────────────────────────────────────────────────────────────
    public enum ThreatType {
        SYN_FLOOD,
        PORT_SCAN,
        HIGH_TRAFFIC,
        ML_ANOMALY
    }

    // ─────────────────────────────────────────────────────────────────────
    // Severity enum
    // ─────────────────────────────────────────────────────────────────────
    public enum Severity {
        LOW, MEDIUM, HIGH;

        public String label() {
            switch (this) {
                case HIGH:   return "[!!] HIGH  ";
                case MEDIUM: return "[!]  MEDIUM";
                case LOW:    return "[i]  LOW   ";
                default:     return "UNKNOWN";
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // ThreatAlert — structured alert object
    // ─────────────────────────────────────────────────────────────────────
    public static class ThreatAlert {
        public final ThreatType type;
        public final String     sourceIp;
        public final String     message;
        public final Severity   severity;
        public final String     timestamp;

        public ThreatAlert(ThreatType type, String sourceIp,
                           String message, Severity severity) {
            this.type      = type;
            this.sourceIp  = sourceIp;
            this.message   = message;
            this.severity  = severity;
            this.timestamp = LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        }

        @Override
        public String toString() {
            return String.format("  %s | %-14s | [%s] %s",
                    severity.label(), type, timestamp, message);
        }
    }
}