using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

namespace FreshFarmMarket.Middleware
{
    public class ReCaptchaService
    {
        private readonly ILogger<ReCaptchaService> _logger;
        private readonly IHttpClientFactory _httpClientFactory;

        public ReCaptchaService(ILogger<ReCaptchaService> logger, IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
        }

        public async Task<bool> VerifyRecaptchaAsync(string token, string secretKey, string verificationUrl)
        {
            try
            {
                var httpClient = _httpClientFactory.CreateClient();
                var requestUrl = $"{verificationUrl}?secret={secretKey}&response={token}";

                var response = await httpClient.GetStringAsync(requestUrl);
                _logger.LogInformation("reCAPTCHA Response: {Response}", response);

                var recaptchaResponse = JsonDocument.Parse(response);

                if (recaptchaResponse.RootElement.TryGetProperty("success", out var successElement) && successElement.GetBoolean())
                {
                    return true;
                }
                else
                {
                    if (recaptchaResponse.RootElement.TryGetProperty("error-codes", out var errorCodesElement))
                    {
                        foreach (var code in errorCodesElement.EnumerateArray())
                        {
                            _logger.LogWarning("reCAPTCHA Error Code: {ErrorCode}", code.GetString());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while verifying reCAPTCHA");
            }

            return false;
        }

    }
}
