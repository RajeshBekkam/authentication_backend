using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using DatabaseSessions.Options;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace DatabaseSessions.Security;

public enum PasswordVerification
{
    Failed,
    Success,
    SuccessRehashNeeded,
}

/// <summary>
/// Argon2id password hashing, stored in PHC string format:
/// $argon2id$v=19$m=19456,t=2,p=1$&lt;salt&gt;$&lt;hash&gt;
/// </summary>
public sealed class Argon2PasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;

    private readonly PasswordHashingOptions _options;
    private readonly Lazy<Task<string>> _dummyHash;

    public Argon2PasswordHasher(IOptions<PasswordHashingOptions> options)
    {
        _options = options.Value;
        _dummyHash = new Lazy<Task<string>>(() => HashAsync(Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))));
    }

    public async Task<string> HashAsync(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = await ComputeAsync(password, salt, _options.MemorySizeKiB, _options.Iterations, _options.Parallelism, HashSize);
        return string.Create(CultureInfo.InvariantCulture,
            $"$argon2id$v=19$m={_options.MemorySizeKiB},t={_options.Iterations},p={_options.Parallelism}${Encode(salt)}${Encode(hash)}");
    }

    public async Task<PasswordVerification> VerifyAsync(string encodedHash, string password)
    {
        if (!TryParse(encodedHash, out var m, out var t, out var p, out var salt, out var expected))
        {
            return PasswordVerification.Failed;
        }

        var actual = await ComputeAsync(password, salt, m, t, p, expected.Length);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            return PasswordVerification.Failed;
        }

        var outdated = m != _options.MemorySizeKiB || t != _options.Iterations || p != _options.Parallelism || expected.Length != HashSize;
        return outdated ? PasswordVerification.SuccessRehashNeeded : PasswordVerification.Success;
    }

    /// <summary>
    /// Performs a full verification against a throwaway hash so that requests for unknown
    /// users take the same time as requests for real users (prevents user enumeration).
    /// </summary>
    public async Task SimulateVerifyAsync(string password) =>
        await VerifyAsync(await _dummyHash.Value, password);

    private static async Task<byte[]> ComputeAsync(string password, byte[] salt, int memoryKiB, int iterations, int parallelism, int length)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memoryKiB,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };
        return await argon2.GetBytesAsync(length);
    }

    private static bool TryParse(string encoded, out int m, out int t, out int p, out byte[] salt, out byte[] hash)
    {
        m = t = p = 0;
        salt = hash = [];

        // ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
        var parts = encoded.Split('$');
        if (parts.Length != 6 || parts[1] != "argon2id" || parts[2] != "v=19") return false;

        foreach (var param in parts[3].Split(','))
        {
            var kv = param.Split('=');
            if (kv.Length != 2 || !int.TryParse(kv[1], NumberStyles.None, CultureInfo.InvariantCulture, out var value)) return false;
            switch (kv[0])
            {
                case "m": m = value; break;
                case "t": t = value; break;
                case "p": p = value; break;
                default: return false;
            }
        }

        // Guard against hashes that would make verification absurdly expensive.
        if (m is < 8 or > 1048576 || t is < 1 or > 20 || p is < 1 or > 16) return false;

        try
        {
            salt = Decode(parts[4]);
            hash = Decode(parts[5]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length >= 8 && hash.Length >= 16;
    }

    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static byte[] Decode(string s) => Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
}
