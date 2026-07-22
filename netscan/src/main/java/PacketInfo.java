import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class PacketInfo {

    private final int    number;
    private final String sourceIp;
    private final String destIp;
    private final String protocol;
    private final int    sourcePort;
    private final int    destPort;
    private final int    size;
    private final String tcpFlags;
    private final String timestamp;

    public PacketInfo(int number, String sourceIp, String destIp,
                      String protocol, int sourcePort, int destPort,
                      int size, String tcpFlags) {
        this.number     = number;
        this.sourceIp   = sourceIp;
        this.destIp     = destIp;
        this.protocol   = protocol;
        this.sourcePort = sourcePort;
        this.destPort   = destPort;
        this.size       = size;
        this.tcpFlags   = tcpFlags;
        this.timestamp  = LocalDateTime.now()
                            .format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));
    }

    public int    getNumber()     { return number;     }
    public String getSourceIp()   { return sourceIp;   }
    public String getDestIp()     { return destIp;     }
    public String getProtocol()   { return protocol;   }
    public int    getSourcePort() { return sourcePort; }
    public int    getDestPort()   { return destPort;   }
    public int    getSize()       { return size;       }
    public String getTcpFlags()   { return tcpFlags;   }
    public String getTimestamp()  { return timestamp;  }

    @Override
    public String toString() {
        String ports = (sourcePort != -1)
            ? String.format("port %d → %d", sourcePort, destPort)
            : "N/A";
        String flags = (tcpFlags != null && !tcpFlags.isEmpty())
            ? "  " + tcpFlags : "";
        return String.format("[%s] #%-4d %-20s → %-20s %-8s %-6d bytes  %-22s%s",
                timestamp, number, sourceIp, destIp,
                protocol, size, ports, flags);
    }
}