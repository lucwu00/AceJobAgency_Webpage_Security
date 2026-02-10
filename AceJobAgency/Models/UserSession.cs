namespace AceJobAgency.Models
{
    public class UserSession
    {
        public int Id { get; set; }
        public int MemberId { get; set; }
        public string SessionId { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;
        public bool IsActive { get; set; } = true;

        public virtual Member? Member { get; set; }
    }
}