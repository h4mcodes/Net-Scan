import org.pcap4j.core.*;
import org.pcap4j.packet.*;

public class PacketCapture {

    private static final int SNAPSHOT_LEN = 65536;
    private static final int TIMEOUT_MS = 50;
    private static final int PACKET_COUNT = 0;

    public static void main(String[] args) throws Exception {

        java.util.List<PcapNetworkInterface> devices = Pcaps.findAllDevs()
                .stream()
                .filter(d -> {
                    try {
                        return !d.isLoopBack() && d.isUp() && !d.getAddresses().isEmpty();
                    } catch (Exception e) {
                        return false;
                    }
                })
                .collect(java.util.stream.Collectors.toList());

        if (devices.isEmpty()) {
            throw new RuntimeException("No active network interfaces found.");
        }

        PcapNetworkInterface device;
        if (devices.size() == 1) {
            device = devices.get(0);
        } else {
            System.out.println("Multiple active network interfaces found:");
            for (int i = 0; i < devices.size(); i++) {
                System.out.printf("%d: %-30s [%s]%n", i, devices.get(i).getName(), devices.get(i).getDescription());
            }
            System.out.print("Select an interface (0-" + (devices.size() - 1) + "): ");
            java.util.Scanner scanner = new java.util.Scanner(System.in);
            int choice = -1;
            try {
                choice = Integer.parseInt(scanner.nextLine().trim());
            } catch (Exception ignored) {}

            if (choice >= 0 && choice < devices.size()) {
                device = devices.get(choice);
            } else {
                System.out.println("Invalid choice, defaulting to 0.");
                device = devices.get(0);
            }
        }

        PacketStats stats = new PacketStats();
        stats.start();

        Runtime.getRuntime().addShutdownHook(new Thread(stats::stop));

        System.out.println("=".repeat(60));
        System.out.println("  Capturing on : " + device.getDescription());
        System.out.println("=".repeat(60));
        printHeader();

        try (PcapHandle handle = device.openLive(
                SNAPSHOT_LEN,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                TIMEOUT_MS)) {

            handle.setFilter("ip or ip6", BpfProgram.BpfCompileMode.OPTIMIZE);

            final int[] counter = { 0 };

            handle.loop(PACKET_COUNT, (PacketListener) packet -> {
                counter[0]++;
                PacketInfo info = PacketParser.parse(packet, counter[0]);
                if (info == null)
                    return;
                stats.record(info);
                System.out.println(info);
            });

        } catch (InterruptedException e) {
            System.out.println("Capture interrupted.");
        }
    }

    private static void printHeader() {
        System.out.printf("%-13s %-5s %-20s %-20s %-8s %-6s %-20s%n",
                "Time", "No.", "Source IP", "Dest IP",
                "Protocol", "Size", "Ports");
        System.out.println("-".repeat(80));
    }
}