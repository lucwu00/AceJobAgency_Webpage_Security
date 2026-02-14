using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using AceJobAgency.Data;

namespace AceJobAgency.Services
{
    public class SessionCleanupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<SessionCleanupService> _logger;
        private readonly TimeSpan _interval = TimeSpan.FromMinutes(5); // Run every 5 minutes

        public SessionCleanupService(IServiceProvider serviceProvider, ILogger<SessionCleanupService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await CleanupExpiredSessions();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error occurred while cleaning up expired sessions");
                }

                await Task.Delay(_interval, stoppingToken);
            }
        }

        private async Task CleanupExpiredSessions()
        {
            using var scope = _serviceProvider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();

            var sessionTimeoutMinutes = configuration.GetValue<int>("SecuritySettings:SessionTimeoutMinutes", 30);
            var cutoffTime = DateTime.UtcNow.AddMinutes(-sessionTimeoutMinutes);

            var expiredSessions = await context.UserSessions
                .Where(s => s.IsActive && s.LastActivityAt < cutoffTime)
                .ToListAsync();

            foreach (var session in expiredSessions)
            {
                session.IsActive = false;
            }

            if (expiredSessions.Any())
            {
                await context.SaveChangesAsync();
                _logger.LogInformation($"Cleaned up {expiredSessions.Count} expired sessions");
            }
        }
    }
}