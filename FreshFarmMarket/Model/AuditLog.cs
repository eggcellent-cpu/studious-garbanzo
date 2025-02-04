using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Model
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Activity { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
    }
}
