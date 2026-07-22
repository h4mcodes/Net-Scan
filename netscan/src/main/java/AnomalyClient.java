import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class AnomalyClient {

    private static final String FLASK_URL        = "http://localhost:5000/predict";
    private static final int    CONNECT_TIMEOUT  = 3;
    private static final int    RESPONSE_TIMEOUT = 5;
    private static final int    MAX_RETRIES      = 2;

    private static int     totalRequests  = 0;
    private static int     successCount   = 0;
    private static int     failureCount   = 0;
    private static int     anomalyCount   = 0;
    private static boolean flaskReachable = true;

    public static AnomalyResult predict(
            double packetsPerSecond,
            int    uniquePorts,
            int    synCount,
            double avgPacketSize,
            double duration) {

        totalRequests++;

        String json = buildJson(packetsPerSecond, uniquePorts,
                                synCount, avgPacketSize, duration);

        log("REQUEST", String.format(
            "pps=%.1f ports=%d syn=%d avgSize=%.0f",
            packetsPerSecond, uniquePorts, synCount, avgPacketSize));

        AnomalyResult result = attemptWithRetry(json);

        if (result.hasError) {
            failureCount++;
            if (flaskReachable) {
                log("ERROR", "Flask unreachable. Is 'python app.py' running?");
                flaskReachable = false;
            }
        } else {
            successCount++;
            flaskReachable = true;
            if (result.isAnomaly) anomalyCount++;

            log("RESPONSE", String.format(
                "%-7s score=%.4f  [calls:%d | anomalies:%d | errors:%d]",
                result.prediction, result.score,
                totalRequests, anomalyCount, failureCount));
        }

        return result;
    }

    private static AnomalyResult attemptWithRetry(String json) {
        AnomalyResult last = null;

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            last = sendRequest(json);
            if (!last.hasError) return last;

            if (attempt < MAX_RETRIES) {
                log("RETRY", "Attempt " + attempt + " failed. Retrying...");
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
            }
        }

        return last;
    }

    private static AnomalyResult sendRequest(String json) {

        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(Timeout.ofSeconds(CONNECT_TIMEOUT))
                .setResponseTimeout(Timeout.ofSeconds(RESPONSE_TIMEOUT))
                .build();

        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultRequestConfig(config)
                .build()) {

            HttpPost post = new HttpPost(FLASK_URL);
            post.setEntity(new StringEntity(json, ContentType.APPLICATION_JSON));
            post.setHeader("Accept", "application/json");

            return client.execute(post, response -> {
                int    status = response.getCode();
                String body   = EntityUtils.toString(response.getEntity());

                if (status == 400) {
                    log("ERROR", "Bad request: " + body);
                    return AnomalyResult.error("Bad request: " + body);
                }
                if (status == 500) {
                    log("ERROR", "Flask internal error: " + body);
                    return AnomalyResult.error("Flask 500: " + body);
                }
                if (status != 200) {
                    log("ERROR", "Unexpected status: " + status);
                    return AnomalyResult.error("HTTP " + status);
                }

                return parseResponse(body);
            });

        } catch (org.apache.hc.client5.http.ConnectTimeoutException e) {
            return AnomalyResult.error("Connection timeout");

        } catch (java.net.ConnectException e) {
            return AnomalyResult.error("Connection refused — Flask not running");

        } catch (Exception e) {
            return AnomalyResult.error("Unexpected: " + e.getMessage());
        }
    }

    private static String buildJson(double pps, int ports, int syn,
                                     double avgSize, double duration) {
        return String.format(java.util.Locale.US,
            "{"                                 +
            "\"packets_per_second\": %.2f, "    +
            "\"unique_ports\": %d, "            +
            "\"syn_count\": %d, "               +
            "\"avg_packet_size\": %.2f, "       +
            "\"duration\": %.2f"                +
            "}",
            pps, ports, syn, avgSize, duration
        );
    }

    private static AnomalyResult parseResponse(String json) {
        if (json.contains("\"error\"")) {
            log("ERROR", "Flask returned error: " + json);
            return AnomalyResult.error("Flask error: " + json);
        }

        boolean isAnomaly = json.contains("\"is_anomaly\": true");
        double  score     = extractScore(json);

        return new AnomalyResult(isAnomaly, isAnomaly ? "ANOMALY" : "NORMAL", score);
    }

    private static double extractScore(String json) {
        try {
            int idx = json.indexOf("\"anomaly_score\":");
            if (idx == -1) return 0.0;

            String after = json.substring(idx + 16).trim();
            StringBuilder sb = new StringBuilder();
            for (char c : after.toCharArray()) {
                if (c == ',' || c == '}') break;
                sb.append(c);
            }
            return Double.parseDouble(sb.toString().trim());

        } catch (NumberFormatException e) {
            log("WARN", "Could not parse anomaly_score");
            return 0.0;
        }
    }

    private static void log(String level, String message) {
        String time = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));
        System.out.printf("  [%s] [%-8s] %s%n", time, level, message);
    }

    public static void printSummary() {
        System.out.println("\n── AnomalyClient Summary ────────────────────────");
        System.out.printf("  %-25s %d%n",   "Total API calls:",    totalRequests);
        System.out.printf("  %-25s %d%n",   "Successful:",         successCount);
        System.out.printf("  %-25s %d%n",   "Failed:",             failureCount);
        System.out.printf("  %-25s %d%n",   "Anomalies detected:", anomalyCount);
        if (successCount > 0) {
            double rate = (double) anomalyCount / successCount * 100;
            System.out.printf("  %-25s %.1f%%%n", "Anomaly rate:", rate);
        }
        System.out.println("─".repeat(50));
    }

    public static class AnomalyResult {
        public final boolean isAnomaly;
        public final String  prediction;
        public final double  score;
        public final String  errorMessage;
        public final boolean hasError;

        public AnomalyResult(boolean isAnomaly, String prediction, double score) {
            this.isAnomaly    = isAnomaly;
            this.prediction   = prediction;
            this.score        = score;
            this.errorMessage = null;
            this.hasError     = false;
        }

        private AnomalyResult(String error) {
            this.isAnomaly    = false;
            this.prediction   = "ERROR";
            this.score        = 0.0;
            this.errorMessage = error;
            this.hasError     = true;
        }

        public static AnomalyResult error(String msg) {
            return new AnomalyResult(msg);
        }

        @Override
        public String toString() {
            if (hasError) return "[ERROR] " + errorMessage;
            return String.format("%-7s (score: %.4f)", prediction, score);
        }
    }
}