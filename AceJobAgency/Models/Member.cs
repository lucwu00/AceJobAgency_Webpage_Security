using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models
{
    public class Member
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [StringLength(10)]
        public string Gender { get; set; } = string.Empty;

        [Required]
        [StringLength(500)] // Encrypted NRIC will be longer
        public string NRIC { get; set; } = string.Empty; // Stored encrypted

        [Required]
        [EmailAddress]
        [StringLength(255)]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        [Required]
        public DateTime DateOfBirth { get; set; }

        [StringLength(255)]
        public string? ResumePath { get; set; }

        [StringLength(1000)]
        public string? WhoAmI { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? LastLoginAt { get; set; }
        public DateTime? PasswordChangedAt { get; set; }

        public int FailedLoginAttempts { get; set; } = 0;

        public DateTime? LockoutEnd { get; set; }

        public bool IsLocked { get; set; } = false;

        // Password history for preventing reuse
        public virtual ICollection<PasswordHistory> PasswordHistories { get; set; } = new List<PasswordHistory>();

        // Audit logs
        public virtual ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();

        // Active sessions
        public virtual ICollection<UserSession> UserSessions { get; set; } = new List<UserSession>();

    }
}