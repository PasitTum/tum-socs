# Multi-stage Dockerfile for TUM OpenSIEM Core & SOC Server
# Build Stage (.NET 8.0 SDK)
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
WORKDIR /src

# Copy project files and restore
COPY Tum.Socs.sln ./
COPY Tum.Log/Tum.Log.csproj ./Tum.Log/
COPY Tum.Siem.Server/Tum.Siem.Server.csproj ./Tum.Siem.Server/
COPY tests/Tum.Log.Tests/Tum.Log.Tests.csproj ./tests/Tum.Log.Tests/

RUN dotnet restore Tum.Siem.Server/Tum.Siem.Server.csproj

# Copy source and publish
COPY . ./
RUN dotnet publish Tum.Siem.Server/Tum.Siem.Server.csproj -c Release -o /app/publish /p:UseAppHost=false

# Runtime Image (.NET 8.0 ASP.NET Alpine)
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS final
WORKDIR /app

RUN apk add --no-cache curl wget

COPY --from=build /app/publish .
COPY rules ./rules

EXPOSE 5200
ENV ASPNETCORE_URLS=http://+:5200
ENV ASPNETCORE_ENVIRONMENT=Production
ENV DOTNET_EnableDiagnostics=0

HEALTHCHECK --interval=20s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:5200/health || exit 1

ENTRYPOINT ["dotnet", "Tum.Siem.Server.dll"]
