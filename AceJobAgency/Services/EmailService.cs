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
            // Mask sensitive information for logging
            var maskedEmail = MaskEmail(email);

            // For development: Log to console/output window (with masked data)
            _logger.LogInformation("========================================");
            _logger.LogInformation("📧 PASSWORD RESET EMAIL");
            _logger.LogInformation($"To: {maskedEmail}");
            _logger.LogInformation("Reset link generated (link hidden for security)");
            _logger.LogInformation("This link expires in 1 hour.");
            _logger.LogInformation("========================================");

            // Also write to console for visibility (with masked data)
            Console.WriteLine("\n========================================");
            Console.WriteLine("📧 PASSWORD RESET EMAIL");
            Console.WriteLine($"To: {maskedEmail}");
            Console.WriteLine("Reset link generated (link hidden for security)");
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

        /// <summary>
        /// Masks email address for secure logging (e.g., j***@example.com)
        /// </summary>
        private string MaskEmail(string email)
        {
            if (string.IsNullOrEmpty(email) || !email.Contains("@"))
                return "***@***.***";

            var parts = email.Split('@');
            var username = parts[0];
            var domain = parts[1];

            // Show first character of username, mask the rest
            var maskedUsername = username.Length > 1
                ? username[0] + new string('*', Math.Min(username.Length - 1, 3))
                : "*";

            return $"{maskedUsername}@{domain}";
        }
    }
}