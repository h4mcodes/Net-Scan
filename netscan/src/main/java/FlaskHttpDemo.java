import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;

public class FlaskHttpDemo {

    public static void main(String[] args) throws Exception {

        // ── Normal traffic test ───────────────────────────────────────────
        String normalJson = "{"
            + "\"packets_per_second\": 50.0,"
            + "\"unique_ports\": 10,"
            + "\"syn_count\": 2,"
            + "\"avg_packet_size\": 500.0,"
            + "\"duration\": 5.0"
            + "}";

        System.out.println("── Test 1: Normal Traffic ───────────────────────");
        sendAndPrint(normalJson);

        // ── Anomalous traffic test ────────────────────────────────────────
        String anomalyJson = "{"
            + "\"packets_per_second\": 999.0,"
            + "\"unique_ports\": 200,"
            + "\"syn_count\": 80,"
            + "\"avg_packet_size\": 1400.0,"
            + "\"duration\": 5.0"
            + "}";

        System.out.println("\n── Test 2: Anomalous Traffic ────────────────────");
        sendAndPrint(anomalyJson);
    }

    private static void sendAndPrint(String json) throws Exception {
        try (CloseableHttpClient client = HttpClients.createDefault()) {

            HttpPost post = new HttpPost("http://localhost:5000/predict");
            post.setEntity(new StringEntity(json, ContentType.APPLICATION_JSON));

            client.execute(post, response -> {
                String body = EntityUtils.toString(response.getEntity());
                System.out.println("Status   : " + response.getCode());
                System.out.println("Response : " + body);

                if (body.contains("\"is_anomaly\": true")) {
                    System.out.println("Result   : ⚠  ANOMALY DETECTED");
                } else {
                    System.out.println("Result   : ✓  Normal traffic");
                }
                return null;
            });
        }
    }
}