using System;
using MySql.Data.MySqlClient;

namespace SecureCoding.MySqlConsoleApp;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Welcome to the Secure Coding MySQL Console App!");

        // Test XSS input validation
        TestXssInput();

        // Example usage of LoginService
        var loginService = new LoginService();
        bool loginResult = loginService.LoginUser("thetnaungsoe", "securepassword123");
        Console.WriteLine($"Login result: {loginResult}");

    }

    public static bool IsValidXSSInput(string input)

    {

        if (string.IsNullOrEmpty(input))

            return true;

        if (input.ToLower().Contains("<script") || input.ToLower().Contains("<iframe"))

            return false;

        return true;

    }

    public static void TestXssInput()

    {

        string maliciousInput = "<script>alert('XSS');</script>";

        bool isValid = IsValidXSSInput(maliciousInput);

        Console.WriteLine(isValid ? "XSS Test Failed" : "XSS Test Passed");

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
            {
                return false; // Invalid character found
            }
        }

        return true; // All characters are valid
    }
}

public class LoginService
{
    private readonly string _connectionString = "server=localhost;user=root;password=199897144;database=Module5;";

    public bool LoginUser(string username, string password)
    {
        string allowedSpecialCharacters = "!@#$%^&*?";

        if (!ValidationHelpers.IsValidInput(username) || !ValidationHelpers.IsValidInput(password, allowedSpecialCharacters))
            return false;

        string query = "SELECT COUNT(*) FROM user WHERE username = @username AND password = @password";

        using (var connection = new MySqlConnection(_connectionString))
        {
            using (var command = new MySqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@username", username);
                command.Parameters.AddWithValue("@password", password);

                connection.Open();
                var count = Convert.ToInt32(command.ExecuteScalar());
                return count > 0;
            }
        }
    }
}