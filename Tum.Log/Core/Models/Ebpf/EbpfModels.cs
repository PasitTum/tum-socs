namespace Tum.Log.Core.Models.Ebpf;

/// <summary>
/// Telemetry event extracted from an eBPF / AF_XDP network packet hook.
/// </summary>
public class EbpfPacketEvent
{
    public Guid EventId { get; set; } = Guid.NewGuid();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string InterfaceName { get; set; } = "eth0";
    public string Protocol { get; set; } = "TCP";
    public string SourceIp { get; set; } = string.Empty;
    public string DestinationIp { get; set; } = string.Empty;
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public int PacketSizeBytes { get; set; }
    public string TcpFlags { get; set; } = string.Empty;
    public bool IsSynScan { get; set; }
    public string? DnsQuery { get; set; }
    public string? TlsSni { get; set; }
    public string? PayloadSnippet { get; set; }
}

/// <summary>
/// Options for configuring kernel eBPF packet sniffing.
/// </summary>
public class EbpfSnifferOptions
{
    public string InterfaceName { get; set; } = "eth0";
    public bool EnableDnsExtraction { get; set; } = true;
    public bool EnableTlsSniExtraction { get; set; } = true;
    public bool AutoStreamToRingBuffer { get; set; } = true;
    public int MaxPayloadSnippetLength { get; set; } = 128;
}

/// <summary>
/// Performance statistics and counters for eBPF packet capture.
/// </summary>
public class EbpfSnifferStats
{
    public long TotalPacketsCaptured { get; set; }
    public long TotalBytesCaptured { get; set; }
    public long TcpPackets { get; set; }
    public long UdpPackets { get; set; }
    public long IcmpPackets { get; set; }
    public long SynScansDetected { get; set; }
    public long DnsQueriesExtracted { get; set; }
}
