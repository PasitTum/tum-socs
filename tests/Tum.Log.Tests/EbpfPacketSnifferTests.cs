using System.Buffers.Binary;
using System.Text;
using Tum.Log.Core.Models.Ebpf;
using Tum.Log.Infrastructure.Ebpf;
using Tum.Trust.Security.Infrastructure.Ingestion;
using Xunit;

namespace Tum.Log.Tests;

public class EbpfPacketSnifferTests
{
    [Fact]
    public void IngestPacket_ValidTcpSynPacket_DetectsSynScanAndExtractsMetadata()
    {
        // Build mock Ethernet + IPv4 + TCP SYN packet
        var packet = CreateMockTcpPacket(
            srcIp: new byte[] { 192, 168, 1, 100 },
            dstIp: new byte[] { 10, 0, 0, 1 },
            srcPort: 54321,
            dstPort: 443,
            tcpFlags: 0x02 // SYN only
        );

        var sniffer = new EbpfPacketSniffer();
        var ev = sniffer.IngestPacket(packet, DateTime.UtcNow);

        Assert.NotNull(ev);
        Assert.Equal("TCP", ev!.Protocol);
        Assert.Equal("192.168.1.100", ev.SourceIp);
        Assert.Equal("10.0.0.1", ev.DestinationIp);
        Assert.Equal(54321, ev.SourcePort);
        Assert.Equal(443, ev.DestinationPort);
        Assert.True(ev.IsSynScan);
        Assert.Contains("SYN", ev.TcpFlags);

        var stats = sniffer.GetStatistics();
        Assert.Equal(1, stats.TotalPacketsCaptured);
        Assert.Equal(1, stats.TcpPackets);
        Assert.Equal(1, stats.SynScansDetected);
    }

    [Fact]
    public void IngestPacket_ValidUdpDnsPacket_ExtractsDnsQuery()
    {
        // Build mock Ethernet + IPv4 + UDP DNS query packet for "api.tum.internal"
        var packet = CreateMockDnsPacket(
            srcIp: new byte[] { 192, 168, 1, 50 },
            dstIp: new byte[] { 8, 8, 8, 8 },
            domain: "api.tum.internal"
        );

        var sniffer = new EbpfPacketSniffer();
        var ev = sniffer.IngestPacket(packet, DateTime.UtcNow);

        Assert.NotNull(ev);
        Assert.Equal("UDP", ev!.Protocol);
        Assert.Equal("192.168.1.50", ev.SourceIp);
        Assert.Equal("8.8.8.8", ev.DestinationIp);
        Assert.Equal(53, ev.DestinationPort);
        Assert.Equal("api.tum.internal", ev.DnsQuery);

        var stats = sniffer.GetStatistics();
        Assert.Equal(1, stats.UdpPackets);
        Assert.Equal(1, stats.DnsQueriesExtracted);
    }

    [Fact]
    public async Task IngestPacket_WithRingBuffer_EnqueuesTelemetryLogEntry()
    {
        var received = new List<Tum.Trust.Security.Core.Models.Logging.TumLogEntry>();
        var tcs = new TaskCompletionSource<bool>();

        await using var ringBuffer = new TumRingBufferIngestor(
            new TumRingBufferOptions
            {
                Capacity = 100,
                BatchSize = 1,
                FlushIntervalMs = 10
            },
            (batch, ct) =>
            {
                lock (received)
                {
                    received.AddRange(batch);
                    tcs.TrySetResult(true);
                }
                return Task.CompletedTask;
            });

        var options = new EbpfSnifferOptions { AutoStreamToRingBuffer = true };
        var sniffer = new EbpfPacketSniffer(options, ringBuffer);

        var packet = CreateMockTcpPacket(
            srcIp: new byte[] { 10, 0, 0, 5 },
            dstIp: new byte[] { 10, 0, 0, 1 },
            srcPort: 12345,
            dstPort: 80,
            tcpFlags: 0x12 // SYN + ACK
        );

        var ev = sniffer.IngestPacket(packet, DateTime.UtcNow);

        Assert.NotNull(ev);
        Assert.False(ev!.IsSynScan);

        var completed = await Task.WhenAny(tcs.Task, Task.Delay(2000));
        Assert.Same(tcs.Task, completed);

        lock (received)
        {
            Assert.Single(received);
            Assert.Equal(Tum.Trust.Security.Core.Models.Logging.LogCategory.AuditTrail, received[0].Category);
            Assert.Contains("10.0.0.5", received[0].PayloadSanitized);
        }
    }

    private static byte[] CreateMockTcpPacket(byte[] srcIp, byte[] dstIp, ushort srcPort, ushort dstPort, byte tcpFlags)
    {
        var list = new List<byte>();

        // Ethernet (14 bytes)
        list.AddRange(new byte[6]); // Dst MAC
        list.AddRange(new byte[6]); // Src MAC
        list.AddRange(new byte[] { 0x08, 0x00 }); // EtherType IPv4

        // IPv4 Header (20 bytes)
        list.Add(0x45); // Ver 4, IHL 5 (20 bytes)
        list.Add(0x00); // DSCP/ECN
        list.AddRange(new byte[] { 0x00, 40 }); // Total Length (20 IP + 20 TCP)
        list.AddRange(new byte[] { 0x12, 0x34 }); // Identification
        list.AddRange(new byte[] { 0x40, 0x00 }); // Flags / Frag
        list.Add(64); // TTL
        list.Add(6);  // Protocol TCP
        list.AddRange(new byte[] { 0x00, 0x00 }); // Checksum
        list.AddRange(srcIp);
        list.AddRange(dstIp);

        // TCP Header (20 bytes)
        byte[] spBytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(spBytes, srcPort);
        list.AddRange(spBytes);

        byte[] dpBytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(dpBytes, dstPort);
        list.AddRange(dpBytes);

        list.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x01 }); // Seq
        list.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // Ack
        list.Add(0x50); // Data offset (5 * 4 = 20 bytes)
        list.Add(tcpFlags); // Flags
        list.AddRange(new byte[] { 0x72, 0x10 }); // Window
        list.AddRange(new byte[] { 0x00, 0x00 }); // Checksum
        list.AddRange(new byte[] { 0x00, 0x00 }); // Urgent

        return list.ToArray();
    }

    private static byte[] CreateMockDnsPacket(byte[] srcIp, byte[] dstIp, string domain)
    {
        var list = new List<byte>();

        // Ethernet (14 bytes)
        list.AddRange(new byte[12]);
        list.AddRange(new byte[] { 0x08, 0x00 });

        // IPv4 Header (20 bytes)
        list.Add(0x45);
        list.Add(0x00);
        list.AddRange(new byte[] { 0x00, 60 });
        list.AddRange(new byte[] { 0x00, 0x01 });
        list.AddRange(new byte[] { 0x00, 0x00 });
        list.Add(64);
        list.Add(17); // UDP
        list.AddRange(new byte[] { 0x00, 0x00 });
        list.AddRange(srcIp);
        list.AddRange(dstIp);

        // UDP Header (8 bytes)
        list.AddRange(new byte[] { 0xC0, 0x01 }); // Src port 49153
        list.AddRange(new byte[] { 0x00, 53 });     // Dst port 53 (DNS)
        list.AddRange(new byte[] { 0x00, 32 });     // Length
        list.AddRange(new byte[] { 0x00, 0x00 }); // Checksum

        // DNS Header (12 bytes)
        list.AddRange(new byte[] { 0x12, 0x34 }); // Tx ID
        list.AddRange(new byte[] { 0x01, 0x00 }); // Standard query
        list.AddRange(new byte[] { 0x00, 0x01 }); // QDCOUNT 1
        list.AddRange(new byte[] { 0x00, 0x00 }); // ANCOUNT 0
        list.AddRange(new byte[] { 0x00, 0x00 }); // NSCOUNT 0
        list.AddRange(new byte[] { 0x00, 0x00 }); // ARCOUNT 0

        // DNS Question QNAME (e.g., 3 a p i 3 t u m 8 i n t e r n a l 0)
        var parts = domain.Split('.');
        foreach (var part in parts)
        {
            list.Add((byte)part.Length);
            list.AddRange(Encoding.ASCII.GetBytes(part));
        }
        list.Add(0x00); // Terminating null

        list.AddRange(new byte[] { 0x00, 0x01 }); // QTYPE A
        list.AddRange(new byte[] { 0x00, 0x01 }); // QCLASS IN

        return list.ToArray();
    }
}
