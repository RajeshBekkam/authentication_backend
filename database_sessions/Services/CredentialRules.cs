namespace DatabaseSessions.Services;

public static class CredentialRules
{
    public const int MinPasswordLength = 12;

    /// <summary>Upper bound keeps Argon2 work bounded and prevents hash-DoS via huge inputs.</summary>
    public const int MaxPasswordLength = 128;

    public static string NormalizeEmail(string email) => email.Trim().ToUpperInvariant();

    /// <summary>NIST 800-63B style: length-based, no composition rules.</summary>
    public static IReadOnlyList<string> ValidatePassword(string password, string email)
    {
        var errors = new List<string>();
        if (password.Length < MinPasswordLength)
            errors.Add($"Password must be at least {MinPasswordLength} characters.");
        if (password.Length > MaxPasswordLength)
            errors.Add($"Password must be at most {MaxPasswordLength} characters.");
        if (string.Equals(password.Trim(), email.Trim(), StringComparison.OrdinalIgnoreCase))
            errors.Add("Password must not be the same as the email address.");
        if (password.Distinct().Count() < 4)
            errors.Add("Password is too repetitive.");
        return errors;
    }
}
