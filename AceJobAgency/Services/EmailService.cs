namespace AceJobAgency.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendPasswordResetEmail(string email, string resetLink)
        {
            // For development: Log to console/output window
            _logger.LogInformation("========================================");
            _logger.LogInformation("📧 PASSWORD RESET EMAIL");
            _logger.LogInformation($"To: {email}");
            _logger.LogInformation($"Reset Link: {resetLink}");
            _logger.LogInformation("This link expires in 1 hour.");
            _logger.LogInformation("========================================");

            // Also write to console for visibility
            Console.WriteLine("\n========================================");
            Console.WriteLine("📧 PASSWORD RESET EMAIL");
            Console.WriteLine($"To: {email}");
            Console.WriteLine($"Reset Link: {resetLink}");
            Console.WriteLine("This link expires in 1 hour.");
            Console.WriteLine("========================================\n");

            // TODO: In production, integrate with SendGrid, AWS SES, or SMTP
            // Example for SendGrid:
            // var apiKey = _configuration["SendGrid:ApiKey"];
            // var client = new SendGridClient(apiKey);
            // var msg = MailHelper.CreateSingleEmail(...);
            // await client.SendEmailAsync(msg);

            await Task.CompletedTask;
        }
    }
}