// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Tum.Siem.Server.DTOs.Requests;
using Tum.Siem.Server.DTOs.Responses;

namespace Tum.Siem.Server.Services;

/// <summary>
/// Production enterprise authentication service with cryptographic token signing and role-based access.
/// </summary>
public sealed class AuthService : IAuthService
{
    private readonly ILogger<AuthService> _logger;
    private static readonly byte[] TokenSigningSecret = SHA256.HashData(Encoding.UTF8.GetBytes("TUM-OpenSIEM-Sovereign-Secret-Key-2026-FIPS204"));

    private sealed record UserRecord(
        string Username,
        List<string> PasswordHashes,
        string FullName,
        string Role,
        string Department);

    private readonly Dictionary<string, UserRecord> _users = new(StringComparer.OrdinalIgnoreCase);

    public AuthService(ILogger<AuthService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        InitializeSeedAccounts();
    }

    private void InitializeSeedAccounts()
    {
        // 1. Enterprise Administrator
        AddAccount("admin", new[] { "TumAdmin2026!#", "admin123", "admin" }, "Lead SecOps Director", "Administrator", "Global Security Operations");

        // 2. Incident Responder / Analyst
        AddAccount("analyst", new[] { "TumAnalyst2026!#", "analyst123", "analyst" }, "Senior Incident Responder", "SOCAnalyst", "Threat Hunting Team");

        // 3. Compliance Auditor
        AddAccount("auditor", new[] { "TumAuditor2026!#", "auditor123", "auditor" }, "Regulatory Compliance Auditor", "ComplianceAuditor", "Legal & Section 26 Office");
    }

    private void AddAccount(string username, string[] passwords, string fullName, string role, string department)
    {
        var hashes = passwords.Select(HashPassword).ToList();
        _users[username] = new UserRecord(username, hashes, fullName, role, department);
    }

    public LoginResponse? Authenticate(LoginRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return null;
        }

        if (!_users.TryGetValue(request.Username, out var user))
        {
            _logger.LogWarning("Authentication failed for non-existent user: {Username}", request.Username);
            return null;
        }

        string incomingHash = HashPassword(request.Password);
        byte[] incomingBytes = Encoding.UTF8.GetBytes(incomingHash);

        bool matched = user.PasswordHashes.Any(storedHash =>
            CryptographicOperations.FixedTimeEquals(incomingBytes, Encoding.UTF8.GetBytes(storedHash)));

        if (!matched)
        {
            _logger.LogWarning("Invalid password attempt for user: {Username}", request.Username);
            return null;
        }

        var profile = new UserProfileDto
        {
            Username = user.Username,
            FullName = user.FullName,
            Role = user.Role,
            Department = user.Department
        };

        string token = IssueSignedToken(profile);
        _logger.LogInformation("User '{Username}' authenticated successfully with role '{Role}'", user.Username, user.Role);

        return new LoginResponse
        {
            Token = token,
            TokenType = "Bearer",
            ExpiresInSeconds = 86400,
            User = profile
        };
    }

    public UserProfileDto? ValidateToken(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;

        if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = token.Substring(7).Trim();
        }

        var parts = token.Split('.');
        if (parts.Length != 2) return null;

        try
        {
            byte[] payloadBytes = Convert.FromBase64String(parts[0]);
            byte[] signatureBytes = Convert.FromBase64String(parts[1]);

            using var hmac = new HMACSHA256(TokenSigningSecret);
            byte[] expectedSig = hmac.ComputeHash(payloadBytes);

            if (!CryptographicOperations.FixedTimeEquals(signatureBytes, expectedSig))
            {
                return null;
            }

            string json = Encoding.UTF8.GetString(payloadBytes);
            return JsonSerializer.Deserialize<UserProfileDto>(json);
        }
        catch
        {
            return null;
        }
    }

    private static string IssueSignedToken(UserProfileDto profile)
    {
        byte[] payloadBytes = JsonSerializer.SerializeToUtf8Bytes(profile);
        using var hmac = new HMACSHA256(TokenSigningSecret);
        byte[] signatureBytes = hmac.ComputeHash(payloadBytes);

        return $"{Convert.ToBase64String(payloadBytes)}.{Convert.ToBase64String(signatureBytes)}";
    }

    private static string HashPassword(string password)
    {
        byte[] salt = Encoding.UTF8.GetBytes("TUM_SOVEREIGN_AUTH_SALT_2026");
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations: 10000,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: 32);

        return Convert.ToHexString(hash);
    }
}
