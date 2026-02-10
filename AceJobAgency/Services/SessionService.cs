using AceJobAgency.Data;
using AceJobAgency.Models;
using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Services
{
    public class SessionService : ISessionService
    {
        private readonly ApplicationDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;

        public SessionService(
            ApplicationDbContext context,
            IHttpContextAccessor httpContextAccessor,
            IConfiguration configuration)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
            _configuration = configuration;
        }

        public async Task CreateSession(int memberId, string sessionId)
        {
            var httpContext = _httpContextAccessor.HttpContext;

            var session = new UserSession
            {
                MemberId = memberId,
                SessionId = sessionId,
                IpAddress = httpContext?.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                UserAgent = httpContext?.Request.Headers["User-Agent"].ToString() ?? "Unknown",
                CreatedAt = DateTime.UtcNow,
                LastActivityAt = DateTime.UtcNow,
                IsActive = true
            };

            _context.UserSessions.Add(session);
            await _context.SaveChangesAsync();
        }

        public async Task<bool> ValidateSession(int memberId, string sessionId)
        {
            var session = await _context.UserSessions
                .FirstOrDefaultAsync(s => s.MemberId == memberId && s.SessionId == sessionId && s.IsActive);

            if (session == null)
                return false;

            // Check session timeout
            var timeoutMinutes = _configuration.GetValue<int>("SecuritySettings:SessionTimeoutMinutes", 30);
            if ((DateTime.UtcNow - session.LastActivityAt).TotalMinutes > timeoutMinutes)
            {
                session.IsActive = false;
                await _context.SaveChangesAsync();
                return false;
            }

            // Update last activity
            session.LastActivityAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            return true;
        }

        public async Task InvalidateSession(string sessionId)
        {
            var session = await _context.UserSessions
                .FirstOrDefaultAsync(s => s.SessionId == sessionId);

            if (session != null)
            {
                session.IsActive = false;
                await _context.SaveChangesAsync();
            }
        }

        public async Task InvalidateAllUserSessions(int memberId)
        {
            var sessions = await _context.UserSessions
                .Where(s => s.MemberId == memberId && s.IsActive)
                .ToListAsync();

            foreach (var session in sessions)
            {
                session.IsActive = false;
            }

            await _context.SaveChangesAsync();
        }

        public async Task<int> GetActiveSessionCount(int memberId)
        {
            var timeoutMinutes = _configuration.GetValue<int>("SecuritySettings:SessionTimeoutMinutes", 30);
            var cutoffTime = DateTime.UtcNow.AddMinutes(-timeoutMinutes);

            return await _context.UserSessions
                .CountAsync(s => s.MemberId == memberId
                    && s.IsActive
                    && s.LastActivityAt > cutoffTime);
        }

        public async Task CleanupExpiredSessions()
        {
            var timeoutMinutes = _configuration.GetValue<int>("SecuritySettings:SessionTimeoutMinutes", 30);
            var cutoffTime = DateTime.UtcNow.AddMinutes(-timeoutMinutes);

            var expiredSessions = await _context.UserSessions
                .Where(s => s.IsActive && s.LastActivityAt < cutoffTime)
                .ToListAsync();

            foreach (var session in expiredSessions)
            {
                session.IsActive = false;
            }

            await _context.SaveChangesAsync();
        }
    }
}