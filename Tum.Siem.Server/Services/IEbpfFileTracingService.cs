using Tum.Log.Core.Models.Ebpf;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Service interface for coordinating kernel eBPF file system hook monitoring,
/// baseline management, and binary tampering simulations in Tum.Siem.Server.
/// </summary>
public interface IEbpfFileTracingService
{
    /// <summary>
    /// Gets overall monitoring status, metrics, and active baseline counts.
    /// </summary>
    EbpfFileMonitorStats GetMonitorStatistics();

    /// <summary>
    /// Ingests a file system hook trace event into the monitor.
    /// </summary>
    EbpfFileEvent? IngestTrace(EbpfFileTraceRaw rawTrace);

    /// <summary>
    /// Registers or updates a binary's expected SHA-256 hash.
    /// </summary>
    void RegisterBaseline(string filePath, string expectedSha256);

    /// <summary>
    /// Retrieves recent detected tampering alerts.
    /// </summary>
    IReadOnlyList<EbpfFileEvent> GetRecentAlerts(int limit = 50);

    /// <summary>
    /// Simulates an adversary modifying a critical system binary to demonstrate detection.
    /// </summary>
    EbpfFileEvent SimulateBinaryTampering(string? targetPath = null, string? attackerProcess = null);

    /// <summary>
    /// Simulates an adversary attempting to wipe/unlink forensic WORM logs.
    /// </summary>
    EbpfFileEvent SimulateLogWipeAttempt(string? logPath = null, string? attackerProcess = null);
}
