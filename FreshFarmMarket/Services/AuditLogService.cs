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
            var auditLog = new AuditLog
            {
                UserId = userId,
                Activity = activity,
                Details = details,
                Timestamp = DateTime.UtcNow,
                IpAddress = "", // Add IP address capture logic
                UserAgent = "" // Add User Agent capture logic
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
    }
}
