import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class AlertEngine {

    // ── Alert level based on Rule + AI combination ────────────────────────
    //
    //   Rule triggered + AI anomaly  →  HIGH
    //   Rule triggered only          →  MEDIUM
    //   AI anomaly only              →  LOW
    //   Neither                      →  NONE (no alert)
    //
    public enum AlertLevel {
        HIGH, MEDIUM, LOW, NONE;

        public String label() {
            switch (this) {
                case HIGH:   return "[ !! ] HIGH  ";
                case MEDIUM: return " [ ! ] MEDIUM";
                case LOW:    return "  [i]  LOW   ";
                default:     return "       NONE  ";
            }
        }

        public String banner() {
            switch (this) {
                case HIGH:   return "████████████████████████████████████████████";
                case MEDIUM: return "--------------------------------------------";
                case LOW:    return "............................................";
                default:     return "";
            }
        }
    }

    // ── Single alert record ───────────────────────────────────────────────
    public static class Alert {
        public final AlertLevel level;
        public final String     threatType;
        public final String     sourceIp;
        public final String     message;
        public final boolean    ruleTriggered;
        public final boolean    aiTriggered;
        public final double     aiScore;
        public final String     timestamp;

        public Alert(AlertLevel level,
                     String     threatType,
                     String     sourceIp,
                     String     message,
                     boolean    ruleTriggered,
                     boolean    aiTriggered,
                     double     aiScore) {
            this.level         = level;
            this.threatType    = threatType;
            this.sourceIp      = sourceIp;
            this.message       = message;
            this.ruleTriggered = ruleTriggered;
            this.aiTriggered   = aiTriggered;
            this.aiScore       = aiScore;
            this.timestamp     = LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        }

        // Evidence string — shows what triggered this alert
        public String evidence() {
            if (ruleTriggered && aiTriggered)
                return String.format("Rule=YES  AI=YES  (score: %.4f)", aiScore);
            if (ruleTriggered)
                return String.format("Rule=YES  AI=NO   (score: %.4f)", aiScore);
            return String.format("Rule=NO   AI=YES  (score: %.4f)", aiScore);
        }

        @Override
        public String toString() {
            return String.format(
                "  %s | %-14s | [%s] %-50s | %s",
                level.label(), threatType, timestamp, message, evidence()
            );
        }
    }

    // ── Alert history (all alerts since start) ────────────────────────────
    private final List<Alert> alertHistory = new CopyOnWriteArrayList<>();

    // ── Session counters ──────────────────────────────────────────────────
    private int highCount   = 0;
    private int mediumCount = 0;
    private int lowCount    = 0;

    // ── Core evaluation method ────────────────────────────────────────────
    // Called every 5s with rule-based threats and ML result
    public List<Alert> evaluate(
            List<ThreatDetector.ThreatAlert> ruleThreats,
            AnomalyClient.AnomalyResult      mlResult) {

        List<Alert> alerts    = new ArrayList<>();
        boolean     aiAnomaly = !mlResult.hasError && mlResult.isAnomaly;
        double      aiScore   = mlResult.hasError  ? 0.0 : mlResult.score;

        // ── Case 1: Rule AND AI both triggered ────────────────────────────
        if (!ruleThreats.isEmpty() && aiAnomaly) {
            for (ThreatDetector.ThreatAlert threat : ruleThreats) {
                Alert alert = new Alert(
                    AlertLevel.HIGH,
                    threat.type.name(),
                    threat.sourceIp,
                    threat.message,
                    true, true, aiScore
                );
                alerts.add(alert);
            }
        }

        // ── Case 2: Only rule triggered ───────────────────────────────────
        else if (!ruleThreats.isEmpty()) {
            for (ThreatDetector.ThreatAlert threat : ruleThreats) {
                Alert alert = new Alert(
                    AlertLevel.MEDIUM,
                    threat.type.name(),
                    threat.sourceIp,
                    threat.message,
                    true, false, aiScore
                );
                alerts.add(alert);
            }
        }

        // ── Case 3: Only AI triggered ─────────────────────────────────────
        else if (aiAnomaly) {
            Alert alert = new Alert(
                AlertLevel.LOW,
                "ML_ANOMALY",
                "GLOBAL",
                String.format("ML model detected anomalous traffic pattern"),
                false, true, aiScore
            );
            alerts.add(alert);
        }

        // ── Case 4: Neither — no alert ────────────────────────────────────
        // alerts list stays empty

        // Store in history and update counters
        for (Alert a : alerts) {
            alertHistory.add(a);
            switch (a.level) {
                case HIGH:   highCount++;   break;
                case MEDIUM: mediumCount++; break;
                case LOW:    lowCount++;    break;
                default:     break;
            }
        }

        return alerts;
    }

    // ── Print alerts to console ───────────────────────────────────────────
    public void printAlerts(List<Alert> alerts) {
        if (alerts.isEmpty()) {
            System.out.println("  Alert engine  → CLEAN  No alerts this window");
            return;
        }

        // Find highest level in this batch
        AlertLevel highest = alerts.stream()
                .map(a -> a.level)
                .min((a, b) -> a.ordinal() - b.ordinal())
                .orElse(AlertLevel.NONE);

        System.out.println("\n  " + highest.banner());

        for (Alert alert : alerts) {
            System.out.println(alert);
        }

        System.out.println("  " + highest.banner());
    }

    // ── Session summary ───────────────────────────────────────────────────
    public void printSummary() {
        System.out.println("\n── AlertEngine Summary ──────────────────────────");
        System.out.printf("  %-25s %d%n", "HIGH alerts:",         highCount);
        System.out.printf("  %-25s %d%n", "MEDIUM alerts:",       mediumCount);
        System.out.printf("  %-25s %d%n", "LOW alerts:",          lowCount);
        System.out.printf("  %-25s %d%n", "Total alerts:",
                          highCount + mediumCount + lowCount);

        // Print last 5 alerts from history
        if (!alertHistory.isEmpty()) {
            System.out.println("\n  Last alerts:");
            int start = Math.max(0, alertHistory.size() - 5);
            for (int i = start; i < alertHistory.size(); i++) {
                System.out.println("  " + alertHistory.get(i));
            }
        }
        System.out.println("─".repeat(50));
    }
}