using System.Net.Mail;
using System.Net;

namespace FreshFarmMarket.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly EmailConfiguration _emailConfig;
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(EmailConfiguration emailConfig, ILogger<EmailSender> logger)
        {
            _emailConfig = emailConfig;
            _logger = logger;
        }

        public async Task SendEmailAsync(string to, string subject, string body)
        {
            try
            {
                var smtpClient = new SmtpClient(_emailConfig.SmtpServer)
                {
                    Port = _emailConfig.Port,
                    Credentials = new NetworkCredential(_emailConfig.Username, _emailConfig.Password),
                    EnableSsl = true,
                    Timeout = 30000
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_emailConfig.From),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };
                mailMessage.To.Add(to);

                await smtpClient.SendMailAsync(mailMessage);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email.");
                throw new Exception($"Email sending failed: {ex.Message}", ex);
            }
        }
    }
}
