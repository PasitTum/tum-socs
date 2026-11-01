// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Tum.Siem.Server.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Register Enterprise OpenSIEM Services & Infrastructure
builder.Services.AddSiemInfrastructure(builder.Configuration);

var app = builder.Build();

// Configure HTTP Middleware Pipeline & Endpoint Routing
app.UseSiemPipeline();

app.Run();

public partial class Program { }
