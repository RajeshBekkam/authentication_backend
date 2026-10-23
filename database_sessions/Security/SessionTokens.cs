using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace DatabaseSessions.Security;

/// <summary>
/// Session tokens are 256-bit random values encoded as base64url (43 chars).
/// Only the SHA-256 hash is persisted, so a database leak does not yield usable tokens.
/// </summary>
public static class SessionTokens
{
    private const int TokenBytes = 32;
    private const int EncodedLength = 43;

    public static string Generate() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(TokenBytes));

    public static string GenerateCsrfToken() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(TokenBytes));

    public static byte[] Hash(string token) => SHA256.HashData(Encoding.ASCII.GetBytes(token));

    /// <summary>Cheap shape check so malformed input never reaches the database.</summary>
    public static bool IsWellFormed(string? token) =>
        token is { Length: EncodedLength } && Base64Url.IsValid(token);

    public static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
