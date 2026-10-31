using Tum.Log.Core.Models.Ebpf;

namespace Tum.Log.Core.Interfaces;

/// <summary>
/// High-throughput eBPF and kernel network telemetry packet sniffer.
/// Captures raw network frames at the link/socket layer, extracts protocol metadata,
/// and streams telemetry into the OpenSIEM RingBuffer.
/// </summary>
public interface IEbpfPacketSniffer : IDisposable
{
    /// <summary>
    /// Gets the operational status of the packet sniffer.
    /// </summary>
    bool IsRunning { get; }

    /// <summary>
    /// Gets total packets and byte capture metrics.
    /// </summary>
    EbpfSnifferStats GetStatistics();

    /// <summary>
    /// Starts capturing packets asynchronously.
    /// </summary>
    ValueTask StartAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Stops capturing packets.
    /// </summary>
    ValueTask StopAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Ingests and parses a raw packet frame (e.g. from AF_XDP, eBPF socket buffer, or test harness).
    /// </summary>
    EbpfPacketEvent? IngestPacket(byte[] rawPacketBytes, DateTime timestamp);
}
