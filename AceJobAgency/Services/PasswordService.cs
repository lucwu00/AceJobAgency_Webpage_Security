using AceJobAgency.Data;
using AceJobAgency.Models;
using Microsoft.EntityFrameworkCore;
using BCrypt.Net;

namespace AceJobAgency.Services
{
    public class PasswordService : IPasswordService
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public PasswordService(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, BCrypt.Net.BCrypt.GenerateSalt(12));
        }

        public bool VerifyPassword(string password, string hashedPassword)
        {
            try
            {
                return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
            }
            catch
            {
                return false;
            }
        }

        public (bool isValid, string message) ValidatePasswordStrength(string password)
        {
            var minLength = _configuration.GetValue<int>("SecuritySettings:PasswordMinLength", 12);

            if (string.IsNullOrWhiteSpace(password))
                return (false, "Password is required.");

            if (password.Length < minLength)
                return (false, $"Password must be at least {minLength} characters long.");

            bool hasUpperCase = password.Any(char.IsUpper);
            bool hasLowerCase = password.Any(char.IsLower);
            bool hasDigit = password.Any(char.IsDigit);
            bool hasSpecialChar = password.Any(ch => !char.IsLetterOrDigit(ch));

            if (!hasUpperCase)
                return (false, "Password must contain at least one uppercase letter.");

            if (!hasLowerCase)
                return (false, "Password must contain at least one lowercase letter.");

            if (!hasDigit)
                return (false, "Password must contain at least one number.");

            if (!hasSpecialChar)
                return (false, "Password must contain at least one special character.");

            // Password strength indicator
            int strength = 0;
            if (password.Length >= 12) strength++;
            if (password.Length >= 16) strength++;
            if (hasUpperCase && hasLowerCase) strength++;
            if (hasDigit) strength++;
            if (hasSpecialChar) strength++;

            string strengthMessage = strength switch
            {
                >= 5 => "Strong password",
                >= 3 => "Medium password - consider making it stronger",
                _ => "Weak password - please use a stronger password"
            };

            return (true, strengthMessage);
        }

        public async Task<bool> CheckPasswordHistory(int memberId, string newPassword)
        {
            var historyCount = _configuration.GetValue<int>("SecuritySettings:PasswordHistoryCount", 2);

            var recentPasswords = await _context.PasswordHistories
                .Where(ph => ph.MemberId == memberId)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(historyCount)
                .ToListAsync();

            foreach (var history in recentPasswords)
            {
                if (VerifyPassword(newPassword, history.PasswordHash))
                {
                    return false; // Password was used recently
                }
            }

            return true; // Password not in recent history
        }

        public async Task AddPasswordToHistory(int memberId, string passwordHash)
        {
            var passwordHistory = new PasswordHistory
            {
                MemberId = memberId,
                PasswordHash = passwordHash,
                CreatedAt = DateTime.UtcNow
            };

            _context.PasswordHistories.Add(passwordHistory);
            await _context.SaveChangesAsync();

            // Keep only the configured number of password history records
            var historyCount = _configuration.GetValue<int>("SecuritySettings:PasswordHistoryCount", 2);
            var oldPasswords = await _context.PasswordHistories
                .Where(ph => ph.MemberId == memberId)
                .OrderByDescending(ph => ph.CreatedAt)
                .Skip(historyCount)
                .ToListAsync();

            if (oldPasswords.Any())
            {
                _context.PasswordHistories.RemoveRange(oldPasswords);
                await _context.SaveChangesAsync();
            }
        }
    }
}