# ==============================================================================
# TUM-OpenSIEM Enterprise Commercial Appliance Dockerfile
# Multi-stage Turnkey Container Build:
#   Stage 1: Web HUD Build (Node.js 20 Alpine)
#   Stage 2: .NET 8.0 SDK Publish (Tum.Siem.Server with Web HUD and Sigma Rules)
#   Stage 3: Hardened Enterprise Runtime Image (.NET 8.0 ASP.NET Alpine)
# ==============================================================================

# STAGE 1: Web HUD Production Bundle
FROM node:20-alpine AS web-builder
WORKDIR /web

# Cache package manifests
COPY Tum.Siem.Web/package*.json ./
RUN npm ci

# Copy web source and compile into static assets
COPY Tum.Siem.Web/ ./
RUN npm run build

# STAGE 2: .NET 8.0 SDK Publish
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS dotnet-builder
WORKDIR /src

# Copy solution and project files for layer caching
COPY Tum.Socs.sln ./
COPY Tum.Log/Tum.Log.csproj ./Tum.Log/
COPY Tum.Siem.Server/Tum.Siem.Server.csproj ./Tum.Siem.Server/
COPY tests/Tum.Log.Tests/Tum.Log.Tests.csproj ./tests/Tum.Log.Tests/

RUN dotnet restore Tum.Siem.Server/Tum.Siem.Server.csproj

# Copy C# sources and rules
COPY Tum.Log/ ./Tum.Log/
COPY Tum.Siem.Server/ ./Tum.Siem.Server/
COPY rules/ ./rules/

# Copy compiled Web HUD from Stage 1 into Tum.Siem.Server/wwwroot
COPY --from=web-builder /Tum.Siem.Server/wwwroot ./Tum.Siem.Server/wwwroot

# Publish Release
RUN dotnet publish Tum.Siem.Server/Tum.Siem.Server.csproj \
    -c Release \
    -o /app/publish \
    /p:UseAppHost=false

# STAGE 3: Minimal Hardened Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS final
WORKDIR /app

RUN apk add --no-cache curl wget tzdata

# Create non-root system user and groups for security hardening
RUN addgroup -S tumsiem && adduser -S tumsiem -G tumsiem && \
    mkdir -p /app/tum_logs /app/rules && \
    chown -R tumsiem:tumsiem /app

COPY --from=dotnet-builder --chown=tumsiem:tumsiem /app/publish .
COPY --chown=tumsiem:tumsiem rules ./rules

USER tumsiem

EXPOSE 5200 514/udp 514/tcp
ENV ASPNETCORE_URLS=http://+:5200
ENV ASPNETCORE_ENVIRONMENT=Production
ENV DOTNET_EnableDiagnostics=0
ENV TZ=Asia/Bangkok

HEALTHCHECK --interval=15s --timeout=4s --retries=3 --start-period=5s \
  CMD wget -qO- http://localhost:5200/health || exit 1

ENTRYPOINT ["dotnet", "Tum.Siem.Server.dll"]
