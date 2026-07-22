import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class PacketStats {

    private final AtomicInteger totalPackets  = new AtomicInteger(0);
    private final AtomicInteger synCount      = new AtomicInteger(0);
    private final AtomicInteger packetsBucket = new AtomicInteger(0);
    private final AtomicLong    totalBytes    = new AtomicLong(0);
    private final AtomicInteger tcpCount      = new AtomicInteger(0);
    private final AtomicInteger udpCount      = new AtomicInteger(0);
    private final AtomicInteger icmpCount     = new AtomicInteger(0);
    private final AtomicInteger otherCount    = new AtomicInteger(0);

    private final Set<Integer> uniquePorts = ConcurrentHashMap.newKeySet();

    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor();

    private final ThreatDetector  threatDetector  = new ThreatDetector();
    private final AlertEngine     alertEngine     = new AlertEngine();
    private final DashboardServer dashboardServer = new DashboardServer();

    private static final int INTERVAL_SECONDS = 5;

    public void start() {
        dashboardServer.start();
        scheduler.scheduleAtFixedRate(
                this::reportAndReset,
                INTERVAL_SECONDS,
                INTERVAL_SECONDS,
                TimeUnit.SECONDS
        );
        System.out.println("  Full pipeline started (every "
                + INTERVAL_SECONDS + "s)\n");
    }

    public void record(PacketInfo info) {
        totalPackets.incrementAndGet();
        packetsBucket.incrementAndGet();
        totalBytes.addAndGet(info.getSize());

        if (info.getSourcePort() != -1) uniquePorts.add(info.getSourcePort());
        if (info.getDestPort()   != -1) uniquePorts.add(info.getDestPort());

        switch (info.getProtocol()) {
            case "TCP":  tcpCount.incrementAndGet();   break;
            case "UDP":  udpCount.incrementAndGet();   break;
            case "ICMP": icmpCount.incrementAndGet();  break;
            default:     otherCount.incrementAndGet(); break;
        }

        if (info.getTcpFlags().contains("SYN")
                && !info.getTcpFlags().contains("ACK")) {
            synCount.incrementAndGet();
        }

        threatDetector.analyze(info);
    }

    private void reportAndReset() {
        int    packets    = packetsBucket.getAndSet(0);
        int    syns       = synCount.getAndSet(0);
        int    ports      = uniquePorts.size();
        long   bytes      = totalBytes.getAndSet(0);
        double pps        = (double) packets / INTERVAL_SECONDS;
        double avgPktSize = packets > 0 ? (double) bytes / packets : 0;

        // ── Console output ────────────────────────────────────────────────
        System.out.println("\n" + "=".repeat(65));
        System.out.printf("  %-28s %d%n",   "Total packets (lifetime):",  totalPackets.get());
        System.out.printf("  %-28s %.1f%n", "Packets/sec (last 5s):",     pps);
        System.out.printf("  %-28s %d%n",   "Unique ports (lifetime):",   ports);
        System.out.printf("  %-28s %d%n",   "SYN count (last 5s):",       syns);
        System.out.printf("  %-28s %.0f%n", "Avg packet size (last 5s):", avgPktSize);
        System.out.println("=".repeat(65));

        // ── ML check ──────────────────────────────────────────────────────
        System.out.print("  ML check      → ");
        AnomalyClient.AnomalyResult mlResult = AnomalyClient.predict(
                pps, ports, syns, avgPktSize, INTERVAL_SECONDS
        );
        if (mlResult.hasError) {
            System.out.println("Flask unreachable.");
        } else {
            System.out.printf("%-7s (score: %.4f)%n",
                    mlResult.prediction, mlResult.score);
        }

        // ── Rule check ────────────────────────────────────────────────────
        List<ThreatDetector.ThreatAlert> ruleThreats = threatDetector.evaluate(
                packets, syns, ports,
                mlResult.hasError ? 0.0 : mlResult.score
        );
        System.out.printf("  Rule check    → %d threat(s)%n", ruleThreats.size());

        // ── Alert engine ──────────────────────────────────────────────────
        System.out.println("  " + "-".repeat(63));
        List<AlertEngine.Alert> alerts = alertEngine.evaluate(ruleThreats, mlResult);
        alertEngine.printAlerts(alerts);

        // ── Build dashboard payload ───────────────────────────────────────
        DashboardServer.DashboardPayload payload = new DashboardServer.DashboardPayload();
        payload.timestamp        = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        payload.totalPackets     = totalPackets.get();
        payload.packetsPerSecond = pps;
        payload.uniquePorts      = ports;
        payload.synCount         = syns;
        payload.avgPacketSize    = avgPktSize;
        payload.tcpCount         = tcpCount.get();
        payload.udpCount         = udpCount.get();
        payload.icmpCount        = icmpCount.get();
        payload.otherCount       = otherCount.get();

        if (!mlResult.hasError) {
            payload.mlPrediction = mlResult.prediction;
            payload.mlScore      = mlResult.score;
            payload.mlAnomaly    = mlResult.isAnomaly;
        } else {
            payload.mlPrediction = "N/A";
            payload.mlScore      = 0.0;
            payload.mlAnomaly    = false;
        }

        if (!alerts.isEmpty()) {
            payload.alertLevel = alerts.get(0).level.name();
            for (AlertEngine.Alert a : alerts) {
                payload.alerts.add(new DashboardServer.DashboardPayload.AlertDto(a.threatType, a.message, a.level.name()));
            }
        } else {
            payload.alertLevel = "NONE";
        }

        // ── Push to browser ───────────────────────────────────────────────
        dashboardServer.pushStats(payload);

        // ── Reset window ──────────────────────────────────────────────────
        threatDetector.resetWindow();
        System.out.println("=".repeat(65) + "\n");
    }

    public void stop() {
        scheduler.shutdown();
        try { dashboardServer.stop(1000); } catch (Exception ignored) {}
        System.out.println("\n══ Final Stats ══════════════════════════════════");
        System.out.printf("  %-28s %d%n", "Total packets:",     totalPackets.get());
        System.out.printf("  %-28s %d%n", "Unique ports seen:", uniquePorts.size());
        System.out.println("═".repeat(50));
        AnomalyClient.printSummary();
        threatDetector.printSummary();
        alertEngine.printSummary();
    }
}