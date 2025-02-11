using FreshFarmMarket.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace FreshFarmMarket.Model
{
    public class MyAuthDbContext : IdentityDbContext<CustomIdentityUser>
    {
        private readonly IConfiguration _configuration; // Declare the configuration field

        public MyAuthDbContext(DbContextOptions<MyAuthDbContext> options, IConfiguration configuration)
            : base(options)
        {
            _configuration = configuration; // Initialize configuration in the constructor
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!_configuration.GetConnectionString("AuthConnectionString").IsNullOrEmpty())
            {
                // Use the connection string from the IConfiguration instance
                optionsBuilder.UseSqlServer(_configuration.GetConnectionString("AuthConnectionString"));
            }
            else
            {
                // Handle the case where the connection string is missing or incorrect
                throw new InvalidOperationException("Connection string is missing or invalid.");
            }
        }

        public DbSet<User> Users { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }

    }
}
