using System.Text;
using Tum.Log.Core.Interfaces;
using Tum.Log.Core.Models.Ebpf;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Implementation of eBPF file tracing service connecting kernel hook monitor
/// with OpenSIEM Server, REST API, and SecOps simulation harnesses.
/// </summary>
public class EbpfFileTracingService : IEbpfFileTracingService
{
    private readonly IEbpfFileHookMonitor _hookMonitor;
    private readonly ILogger<EbpfFileTracingService> _logger;

    public EbpfFileTracingService(
        IEbpfFileHookMonitor hookMonitor,
        ILogger<EbpfFileTracingService> logger)
    {
        _hookMonitor = hookMonitor;
        _logger = logger;
    }

    /// <inheritdoc />
    public EbpfFileMonitorStats GetMonitorStatistics()
    {
        return _hookMonitor.GetStatistics();
    }

    /// <inheritdoc />
    public EbpfFileEvent? IngestTrace(EbpfFileTraceRaw rawTrace)
    {
        var ev = _hookMonitor.IngestFileSyscall(rawTrace);
        if (ev != null && ev.IsTampering)
        {
            _logger.LogWarning("[eBPF FIM] Security Threat Intercepted: {Details}", ev.ThreatDetails);
        }
        return ev;
    }

    /// <inheritdoc />
    public void RegisterBaseline(string filePath, string expectedSha256)
    {
        _hookMonitor.RegisterBinaryBaseline(filePath, expectedSha256);
        _logger.LogInformation("[eBPF FIM] Baseline registered for {Path}: {Hash}", filePath, expectedSha256);
    }

    /// <inheritdoc />
    public IReadOnlyList<EbpfFileEvent> GetRecentAlerts(int limit = 50)
    {
        return _hookMonitor.GetRecentTamperingAlerts(limit);
    }

    /// <inheritdoc />
    public EbpfFileEvent SimulateBinaryTampering(string? targetPath = null, string? attackerProcess = null)
    {
        string target = targetPath ?? "/usr/bin/sudo";
        string attacker = attackerProcess ?? "malware_dropper.bin";

        // Generate synthetic malicious payload modification
        byte[] maliciousBytes = Encoding.UTF8.GetBytes($"MALICIOUS_BACKDOOR_PAYLOAD_{Guid.NewGuid()}");

        var rawTrace = new EbpfFileTraceRaw
        {
            Pid = 9981,
            Uid = 0,
            ProcessName = attacker,
            FilePath = target,
            Syscall = EbpfFileSyscall.Write,
            BufferContent = maliciousBytes,
            Timestamp = DateTime.UtcNow
        };

        var result = _hookMonitor.IngestFileSyscall(rawTrace);
        _logger.LogWarning("[eBPF FIM Simulation] Executed binary tampering simulation on {Target}", target);
        return result!;
    }

    /// <inheritdoc />
    public EbpfFileEvent SimulateLogWipeAttempt(string? logPath = null, string? attackerProcess = null)
    {
        string target = logPath ?? "/var/log/tum-siem/tum_logs_audit.jsonl";
        string attacker = attackerProcess ?? "rootkit_wiper";

        var rawTrace = new EbpfFileTraceRaw
        {
            Pid = 9982,
            Uid = 0,
            ProcessName = attacker,
            FilePath = target,
            Syscall = EbpfFileSyscall.UnlinkAt,
            Timestamp = DateTime.UtcNow
        };

        var result = _hookMonitor.IngestFileSyscall(rawTrace);
        _logger.LogWarning("[eBPF FIM Simulation] Executed log wiping simulation on {Target}", target);
        return result!;
    }
}
