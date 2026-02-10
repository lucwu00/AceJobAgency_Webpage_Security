namespace AceJobAgency.Services
{
    public interface IAuditService
    {
        Task LogActivity(int? memberId, string action, string? details = null);
    }
}