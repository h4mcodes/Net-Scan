import com.google.gson.Gson;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class DashboardServer extends WebSocketServer {

    private static final int PORT = 8080;
    private static final Gson gson = new Gson();

    private final List<WebSocket> clients = new CopyOnWriteArrayList<>();

    public DashboardServer() {
        super(new InetSocketAddress(PORT));
        setReuseAddr(true);
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        clients.add(conn);
        System.out.println("  [Dashboard] Browser connected: "
                + conn.getRemoteSocketAddress());
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        clients.remove(conn);
        System.out.println("  [Dashboard] Browser disconnected");
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        // reserved for future browser → server commands
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        System.err.println("  [Dashboard] Error: " + ex.getMessage());
    }

    @Override
    public void onStart() {
        System.out.println("  [Dashboard] WebSocket server started → ws://localhost:" + PORT);
        System.out.println("  [Dashboard] Open dashboard.html in Chrome to view live data");
    }

    // Called every 5s from PacketStats
    public void pushStats(DashboardPayload payload) {
        if (clients.isEmpty())
            return;
        String json = gson.toJson(payload);
        for (WebSocket client : clients) {
            if (client.isOpen()) {
                client.send(json);
            }
        }
    }

    // ── Payload sent to browser ───────────────────────────────────────────
    public static class DashboardPayload {
        public String timestamp;
        public int totalPackets;
        public double packetsPerSecond;
        public int uniquePorts;
        public int synCount;
        public double avgPacketSize;
        public String mlPrediction;
        public double mlScore;
        public boolean mlAnomaly;
        public String alertLevel;
        public List<AlertDto> alerts = new ArrayList<>();
        public int tcpCount;
        public int udpCount;
        public int icmpCount;
        public int otherCount;

        public static class AlertDto {
            public String type;
            public String message;
            public String level;

            public AlertDto(String type, String message, String level) {
                this.type = type;
                this.message = message;
                this.level = level;
            }
        }
    }
}