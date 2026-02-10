namespace AceJobAgency.Services
{
    public interface ISessionService
    {
        Task CreateSession(int memberId, string sessionId);
        Task<bool> ValidateSession(int memberId, string sessionId);
        Task InvalidateSession(string sessionId);
        Task InvalidateAllUserSessions(int memberId);
        Task<int> GetActiveSessionCount(int memberId);
        Task CleanupExpiredSessions();
    }
}