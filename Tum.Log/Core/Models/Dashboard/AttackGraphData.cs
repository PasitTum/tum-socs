// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;

namespace Tum.Trust.Security.Core.Models.Dashboard
{
    /// <summary>
    /// Node representation in the SIEM threat correlation and attack graph visualization.
    /// </summary>
    public class AttackGraphNode
    {
        public string Id { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public string Type { get; set; } = "AttackerIp"; // AttackerIp, TargetAsset, MitreTechnique, Application
        public string RiskLevel { get; set; } = "Medium";
        public double Value { get; set; } = 1.0;
    }

    /// <summary>
    /// Directed edge representing attack trajectories, technique usages, or exfiltration paths.
    /// </summary>
    public class AttackGraphEdge
    {
        public string Source { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Relation { get; set; } = "Attacks"; // Attacks, Leverages, ExfiltratesFrom
        public string Severity { get; set; } = "High";
        public int Count { get; set; } = 1;
    }

    /// <summary>
    /// Complete graph model rendered by WebGL / Canvas visualizers in the Web Dashboard.
    /// </summary>
    public class AttackGraphData
    {
        public List<AttackGraphNode> Nodes { get; set; } = new List<AttackGraphNode>();
        public List<AttackGraphEdge> Edges { get; set; } = new List<AttackGraphEdge>();
    }
}
