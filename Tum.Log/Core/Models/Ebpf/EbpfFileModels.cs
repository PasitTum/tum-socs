namespace Tum.Log.Core.Models.Ebpf;

/// <summary>
/// Kernel filesystem syscall intercepted by eBPF tracepoints.
/// </summary>
public enum EbpfFileSyscall
{
    OpenAt,
    Write,
    UnlinkAt,
    RenameAt,
    Chmod,
    Chown,
    MmapExec,
    Truncate
}

/// <summary>
/// High-level filesystem operation category.
/// </summary>
public enum EbpfFileOperation
{
    Read,
    Modify,
    Delete,
    Rename,
    PermissionChange,
    Execute
}

/// <summary>
/// Raw eBPF filesystem trace event captured from kernel tracepoint / kprobe.
/// </summary>
public class EbpfFileTraceRaw
{
    public int Pid { get; set; }
    public int Uid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public EbpfFileSyscall Syscall { get; set; }
    public byte[]? BufferContent { get; set; }
    public string? NewFilePath { get; set; }
    public string? ModeOrPermissions { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Enriched eBPF filesystem telemetry and binary tampering event.
/// </summary>
public class EbpfFileEvent
{
    public Guid EventId { get; set; } = Guid.NewGuid();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public int ProcessId { get; set; }
    public int UserId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string? DestinationPath { get; set; }
    public EbpfFileSyscall Syscall { get; set; }
    public EbpfFileOperation Operation { get; set; }
    public string? PreviousSha256 { get; set; }
    public string? CurrentSha256 { get; set; }
    public long FileSizeBytes { get; set; }
    public string? FilePermissions { get; set; }
    public bool IsTampering { get; set; }
    public string? ThreatDetails { get; set; }
    public string? MitreTechniqueId { get; set; }
    public string Severity { get; set; } = "Information";
}

/// <summary>
/// Configuration options for the kernel eBPF filesystem hook monitor.
/// </summary>
public class EbpfFileHookOptions
{
    public bool EnableBinaryIntegrityVerification { get; set; } = true;
    public bool AutoStreamToRingBuffer { get; set; } = true;
    public bool DetectRansomwarePatterns { get; set; } = true;
    public bool DetectAntiForensicLogWiping { get; set; } = true;
    public List<string> CriticalBinaryPaths { get; set; } = new()
    {
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/pam.d",
        "C:\\Windows\\System32",
        "C:\\Program Files\\OpenSIEM"
    };
    public List<string> LogLedgerPaths { get; set; } = new()
    {
        "tum_logs",
        "/var/log/tum-siem",
        ".jsonl"
    };
}

/// <summary>
/// Operational statistics for kernel eBPF filesystem hook engine.
/// </summary>
public class EbpfFileMonitorStats
{
    public long TotalFileEventsCaptured { get; set; }
    public long BinaryModificationsDetected { get; set; }
    public long TamperingAlertsGenerated { get; set; }
    public long DeletionsIntercepted { get; set; }
    public long PermissionEscalations { get; set; }
    public long RansomwarePatternsDetected { get; set; }
    public int MonitoredBaselinesCount { get; set; }
}
