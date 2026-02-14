namespace AceJobAgency.Services
{
    public interface IEmailService
    {
        Task SendPasswordResetEmail(string email, string resetLink);
    }
}