using AceJobAgency.Data;
using AceJobAgency.Models;

namespace AceJobAgency.Services
{
    public class AuditService : IAuditService
    {
        private readonly ApplicationDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuditService(ApplicationDbContext context, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task LogActivity(int? memberId, string action, string? details = null)
        {
            var httpContext = _httpContextAccessor.HttpContext;

            var auditLog = new AuditLog
            {
                MemberId = memberId,
                Action = action,
                IpAddress = httpContext?.Connection.RemoteIpAddress?.ToString(),
                UserAgent = httpContext?.Request.Headers["User-Agent"].ToString(),
                CreatedAt = DateTime.UtcNow,
                Details = details
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
    }
}