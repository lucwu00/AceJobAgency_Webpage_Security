namespace AceJobAgency.Models
{
    public class PasswordHistory
    {
        public int Id { get; set; }
        public int MemberId { get; set; }
        public string PasswordHash { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public virtual Member? Member { get; set; }
    }
}