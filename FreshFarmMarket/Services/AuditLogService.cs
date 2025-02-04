using FreshFarmMarket.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace FreshFarmMarket.Services
{
    public class AuditLogService
    {
        private readonly MyAuthDbContext _context;
        private readonly ILogger<AuditLogService> _logger;

        public AuditLogService(MyAuthDbContext context, ILogger<AuditLogService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task LogActivityAsync(string userId, string activity, string details)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    UserId = userId,
                    Activity = activity,
                    Details = details,
                    Timestamp = DateTime.UtcNow,
                    IpAddress = "",
                    UserAgent = ""
                };

                Console.WriteLine($"Adding audit log for user: {userId}");
                _logger.LogInformation($"Adding audit log for user: {userId}");

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();

                Console.WriteLine("Audit log saved successfully.");
                _logger.LogInformation("Audit log saved successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving audit log: {ex.Message}");
                _logger.LogError($"Error saving audit log: {ex}");
            }
        }

    }
}
