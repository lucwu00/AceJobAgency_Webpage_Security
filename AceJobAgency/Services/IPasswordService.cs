namespace AceJobAgency.Services
{
    public interface IPasswordService
    {
        string HashPassword(string password);
        bool VerifyPassword(string password, string hashedPassword);
        (bool isValid, string message) ValidatePasswordStrength(string password);
        Task<bool> CheckPasswordHistory(int memberId, string newPassword);
        Task AddPasswordToHistory(int memberId, string passwordHash);
    }
}