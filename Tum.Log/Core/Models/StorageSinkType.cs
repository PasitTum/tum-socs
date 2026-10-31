// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Tum.Trust.Security.Core.Models.Logging
{
    /// <summary>
    /// Storage destination sink types supported by TUMLog for sovereign compliance and SIEM ingestion.
    /// </summary>
    public enum StorageSinkType
    {
        /// <summary>
        /// Local immutable WORM file storage with SHA-256 Merkle chain chaining.
        /// </summary>
        LocalWormFile = 1,

        /// <summary>
        /// Enterprise Syslog server over TLS or UDP/TCP conforming to RFC 5424.
        /// </summary>
        SyslogRfc5424 = 2,

        /// <summary>
        /// Elasticsearch or OpenSearch cluster REST ingestion.
        /// </summary>
        ElasticsearchOpenSearch = 3,

        /// <summary>
        /// Cloud Object Storage with Object Lock (AWS S3, MinIO, Cloudflare R2).
        /// </summary>
        AwsS3ObjectLock = 4,

        /// <summary>
        /// Azure Immutable Blob Storage or Event Hubs.
        /// </summary>
        AzureBlobStorage = 5,

        /// <summary>
        /// Apache Kafka or Redpanda distributed streaming topic.
        /// </summary>
        KafkaStreaming = 6,

        /// <summary>
        /// High-speed gRPC or HTTP/2 TUMLog Collector node.
        /// </summary>
        GrpcCollector = 7
    }
}
