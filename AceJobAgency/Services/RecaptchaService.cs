using System.Net.Http;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

namespace AceJobAgency.Services
{
    public interface IRecaptchaService
    {
        Task<RecaptchaVerificationResult?> VerifyAsync(string token, string? remoteIp = null);
    }

    public class RecaptchaService : IRecaptchaService
    {
        private readonly HttpClient _http;
        private readonly string? _secret;

        public RecaptchaService(HttpClient http, IConfiguration config)
        {
            _http = http;
            _secret = config["ReCaptcha:SecretKey"];
        }

        public async Task<RecaptchaVerificationResult?> VerifyAsync(string token, string? remoteIp = null)
        {
            if (string.IsNullOrWhiteSpace(_secret) || string.IsNullOrWhiteSpace(token))
                return null;

            var form = new List<KeyValuePair<string, string>>
            {
                new("secret", _secret),
                new("response", token)
            };

            if (!string.IsNullOrWhiteSpace(remoteIp))
                form.Add(new("remoteip", remoteIp));

            using var content = new FormUrlEncodedContent(form);
            using var resp = await _http.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            if (!resp.IsSuccessStatusCode) return null;

            using var stream = await resp.Content.ReadAsStreamAsync();
            return await JsonSerializer.DeserializeAsync<RecaptchaVerificationResult>(stream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
    }

    public class RecaptchaVerificationResult
    {
        public bool Success { get; set; }
        public double Score { get; set; }
        public string? Action { get; set; }
        public string? Hostname { get; set; }
        public string[]? ErrorCodes { get; set; }
    }
}