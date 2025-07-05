using System;
using System.Security.Cryptography;
using System.Text;
using MySql.Data.MySqlClient;

namespace SecureCoding.MySqlConsoleApp;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("🔐 Welcome to the Secure Coding MySQL Console App!");
        DotNetEnv.Env.Load(); // Load .env variables

        TestXssInput();
        TestSqlInjection();

        var loginService = new LoginService();
        bool loginResult = loginService.LoginUser("thetnaungsoe", "securepassword123");
        Console.WriteLine($"Login result: {(loginResult ? "✅ Success" : "❌ Failed")}");
    }

    public static bool IsValidXSSInput(string input)
    {
        if (string.IsNullOrEmpty(input))
            return true;

        string lowered = input.ToLowerInvariant();

        return !(lowered.Contains("<script") ||
                 lowered.Contains("<iframe") ||
                 lowered.Contains("onerror=") ||
                 lowered.Contains("onload=") ||
                 lowered.Contains("alert(") ||
                 lowered.Contains("javascript:"));
    }

    public static void TestXssInput()
    {
        string maliciousInput = "<img src=x onerror=alert('XSS')>";
        bool isValid = IsValidXSSInput(maliciousInput);
        Console.WriteLine(isValid ? "⚠️ XSS Test Failed" : "✅ XSS Blocked");
    }

    public static void TestSqlInjection()
    {
        var loginService = new LoginService();
        bool result = loginService.LoginUser("' OR 1=1 --", "anyPassword");
        Console.WriteLine(result ? "⚠️ SQL Injection Test Failed" : "✅ SQL Injection Blocked");
    }
}

public static class ValidationHelpers
{
    public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
    {
        if (string.IsNullOrEmpty(input))
            return false;

        var allowedChars = allowedSpecialCharacters.ToHashSet();

        foreach (char c in input)
        {
            if (!char.IsLetterOrDigit(c) && !allowedChars.Contains(c))
                return false;
        }

        return true;
    }
}

public class LoginService
{
    private readonly string _connectionString;

    public LoginService()
    {
        _connectionString = Environment.GetEnvironmentVariable("connection_string")
            ?? throw new InvalidOperationException("Missing 'connection_string' in environment variables.");
    }

    public bool LoginUser(string username, string password)
    {
        string allowedSpecialCharacters = "!@#$%^&*?";

        if (!ValidationHelpers.IsValidInput(username) || !ValidationHelpers.IsValidInput(password, allowedSpecialCharacters))
            return false;

        string query = "SELECT COUNT(*) FROM user WHERE username = @username AND password = @password";

        using var connection = new MySqlConnection(_connectionString);
        using var command = new MySqlCommand(query, connection);

        command.Parameters.AddWithValue("@username", username);
        command.Parameters.AddWithValue("@password", PasswordHasher.Hash(password));

        connection.Open();
        int count = Convert.ToInt32(command.ExecuteScalar());
        return count > 0;
    }

    public static class PasswordHasher
    {
        public static string Hash(string password)
        {
            using var sha = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(password);
            var hash = sha.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
    }
}
