import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

public class PacketParser {

    public static PacketInfo parse(Packet packet, int number) {

        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        if (ipv4 != null) {
            return buildPacketInfo(
                number,
                ipv4.getHeader().getSrcAddr().getHostAddress(),
                ipv4.getHeader().getDstAddr().getHostAddress(),
                resolveProtocol(ipv4.getHeader().getProtocol()),
                packet
            );
        }

        IpV6Packet ipv6 = packet.get(IpV6Packet.class);
        if (ipv6 != null) {
            return buildPacketInfo(
                number,
                ipv6.getHeader().getSrcAddr().getHostAddress(),
                ipv6.getHeader().getDstAddr().getHostAddress(),
                resolveProtocol(ipv6.getHeader().getNextHeader()),
                packet
            );
        }

        return null;
    }

    private static PacketInfo buildPacketInfo(int number, String srcIp,
                                               String dstIp, String protocol,
                                               Packet packet) {
        int    srcPort = -1;
        int    dstPort = -1;
        String flags   = "";

        if (protocol.equals("TCP")) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            if (tcp != null) {
                srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                dstPort = tcp.getHeader().getDstPort().valueAsInt();
                flags   = extractTcpFlags(tcp);
            }
        } else if (protocol.equals("UDP")) {
            UdpPacket udp = packet.get(UdpPacket.class);
            if (udp != null) {
                srcPort = udp.getHeader().getSrcPort().valueAsInt();
                dstPort = udp.getHeader().getDstPort().valueAsInt();
            }
        }

        return new PacketInfo(number, srcIp, dstIp, protocol,
                              srcPort, dstPort, packet.length(), flags);
    }

    private static String resolveProtocol(IpNumber proto) {
        if (proto.equals(IpNumber.TCP))    return "TCP";
        if (proto.equals(IpNumber.UDP))    return "UDP";
        if (proto.equals(IpNumber.ICMPV4)) return "ICMP";
        if (proto.equals(IpNumber.ICMPV6)) return "ICMPv6";
        return "OTHER(" + proto.value() + ")";
    }

    private static String extractTcpFlags(TcpPacket tcp) {
        TcpPacket.TcpHeader h = tcp.getHeader();
        StringBuilder f = new StringBuilder("[");
        if (h.getSyn()) f.append("SYN ");
        if (h.getAck()) f.append("ACK ");
        if (h.getFin()) f.append("FIN ");
        if (h.getRst()) f.append("RST ");
        if (h.getPsh()) f.append("PSH ");
        if (h.getUrg()) f.append("URG ");
        String result = f.toString().trim();
        return result.equals("[") ? "" : result + "]";
    }
}