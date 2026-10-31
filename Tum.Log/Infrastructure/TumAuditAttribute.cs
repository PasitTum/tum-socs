// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using Tum.Trust.Security.Core.Models.Logging;

namespace Tum.Trust.Security.Infrastructure.Logging
{
    /// <summary>
    /// Declarative AOP attribute that marks a controller action, service method, or repository method
    /// for automatic audit capture, PII redaction, and tamper-proof compliance logging.
    /// Eliminates developer confusion regarding where to place log statements in legacy spaghetti codebases.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
    public class TumAuditAttribute : Attribute
    {
        /// <summary>
        /// Gets the logical event name for the annotated action (e.g. 'User.Checkout', 'Profile.View').
        /// </summary>
        public string EventName { get; }

        /// <summary>
        /// Gets the functional category for the log entry.
        /// </summary>
        public LogCategory Category { get; set; } = LogCategory.AuditTrail;

        /// <summary>
        /// Gets or sets a value indicating whether method arguments should be automatically captured and sanitized.
        /// </summary>
        public bool CaptureParameters { get; set; } = true;

        /// <summary>
        /// Gets or sets the severity level for the generated log entry.
        /// </summary>
        public string Severity { get; set; } = "Information";

        /// <summary>
        /// Initializes a new instance of the <see cref="TumAuditAttribute"/> class.
        /// </summary>
        /// <param name="eventName">The unique event identifier.</param>
        public TumAuditAttribute(string eventName)
        {
            EventName = eventName ?? throw new ArgumentNullException(nameof(eventName));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TumAuditAttribute"/> class.
        /// </summary>
        /// <param name="eventName">The unique event identifier.</param>
        /// <param name="category">The log category.</param>
        public TumAuditAttribute(string eventName, LogCategory category)
        {
            EventName = eventName ?? throw new ArgumentNullException(nameof(eventName));
            Category = category;
        }
    }
}
