using System.Text.Json.Serialization;

namespace AceJobAgency.Services
{
    public interface IRecaptchaService
    {
        Task<bool> VerifyToken(string token);
    }

    public class RecaptchaService : IRecaptchaService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;

        public RecaptchaService(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _configuration = configuration;
        }

        public async Task<bool> VerifyToken(string token)
        {
            try
            {
                var secretKey = _configuration["ReCaptcha:SecretKey"];
                var minScore = _configuration.GetValue<double>("ReCaptcha:MinimumScore", 0.5);

                var response = await _httpClient.PostAsync(
                    $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}",
                    null);

                if (!response.IsSuccessStatusCode)
                    return false;

                var jsonString = await response.Content.ReadAsStringAsync();
                var result = System.Text.Json.JsonSerializer.Deserialize<RecaptchaResponse>(jsonString);

                return result?.Success == true && result.Score >= minScore;
            }
            catch
            {
                return false;
            }
        }
    }

    public class RecaptchaResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("score")]
        public double Score { get; set; }

        [JsonPropertyName("action")]
        public string? Action { get; set; }

        [JsonPropertyName("challenge_ts")]
        public string? ChallengeTs { get; set; }

        [JsonPropertyName("hostname")]
        public string? Hostname { get; set; }
    }
}