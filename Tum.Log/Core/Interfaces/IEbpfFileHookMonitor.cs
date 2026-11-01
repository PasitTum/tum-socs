using Tum.Log.Core.Models.Ebpf;

namespace Tum.Log.Core.Interfaces;

/// <summary>
/// Kernel filesystem telemetry and binary tampering detection engine via eBPF tracepoints.
/// Intercepts binary modification, unlinking, and permission tampering in real-time.
/// </summary>
public interface IEbpfFileHookMonitor : IDisposable
{
    /// <summary>
    /// Gets the operational status of the filesystem hook monitor.
    /// </summary>
    bool IsRunning { get; }

    /// <summary>
    /// Gets performance statistics and counters for filesystem hooks.
    /// </summary>
    EbpfFileMonitorStats GetStatistics();

    /// <summary>
    /// Starts capturing filesystem tracepoints asynchronously.
    /// </summary>
    ValueTask StartAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Stops capturing filesystem tracepoints.
    /// </summary>
    ValueTask StopAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Registers or updates the known authentic cryptographic baseline SHA-256 for a binary.
    /// </summary>
    void RegisterBinaryBaseline(string filePath, string expectedSha256);

    /// <summary>
    /// Gets the registered baseline SHA-256 hash for a specified binary, if available.
    /// </summary>
    string? GetBinaryBaseline(string filePath);

    /// <summary>
    /// Verifies raw binary content bytes against the registered cryptographic baseline.
    /// </summary>
    bool VerifyBinaryIntegrity(string filePath, byte[] fileContent);

    /// <summary>
    /// Ingests and processes a raw eBPF filesystem tracepoint event.
    /// </summary>
    EbpfFileEvent? IngestFileSyscall(EbpfFileTraceRaw rawTrace);

    /// <summary>
    /// Retrieves recent binary tampering or suspicious filesystem alerts.
    /// </summary>
    IReadOnlyList<EbpfFileEvent> GetRecentTamperingAlerts(int limit = 50);
}
