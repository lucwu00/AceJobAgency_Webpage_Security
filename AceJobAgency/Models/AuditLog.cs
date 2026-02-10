namespace AceJobAgency.Models
{
    public class AuditLog
    {
        public int Id { get; set; }
        public int? MemberId { get; set; }
        public string Action { get; set; } = string.Empty;
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string? Details { get; set; }

        public virtual Member? Member { get; set; }
    }
}