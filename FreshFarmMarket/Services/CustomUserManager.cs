using FreshFarmMarket.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FreshFarmMarket.Services
{
    public class CustomUserManager : UserManager<CustomIdentityUser>
    {
        private readonly MyAuthDbContext _dbContext;
        private readonly ILogger<CustomUserManager> _logger;  

        public CustomUserManager(
            MyAuthDbContext dbContext,
            IUserStore<CustomIdentityUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<CustomIdentityUser> passwordHasher,
            IEnumerable<IUserValidator<CustomIdentityUser>> userValidators,
            IEnumerable<IPasswordValidator<CustomIdentityUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<CustomUserManager> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            _dbContext = dbContext;
            _logger = logger;
        }

        public async Task<IdentityResult> ChangePasswordWithPolicyAsync(CustomIdentityUser identityUser, string oldPassword, string newPassword)
        {
            if (identityUser == null)
            {
                return IdentityResult.Failed(new IdentityError { Description = "User cannot be null." });
            }

            // Retrieve User entity from the database using Email (not UserID)
            var userFromDb = await _dbContext.Users.OfType<User>().FirstOrDefaultAsync(u => u.Email == identityUser.Email);
            if (userFromDb == null)
            {
                return IdentityResult.Failed(new IdentityError { Description = "User not found." });
            }

            _logger.LogInformation("Checking password history for user {UserId}.", userFromDb.UserID);

            // Check password history using the UserID (Guid) from userFromDb
            var lastTwoPasswords = await _dbContext.PasswordHistories
                .AsNoTracking()
                .Where(ph => ph.UserId == userFromDb.UserID.ToString()) // Compare UserID (Guid converted to string)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(2)
                .ToListAsync();

            _logger.LogInformation("Found {PasswordCount} passwords in history for user {UserId}.", lastTwoPasswords.Count, userFromDb.UserID);

            foreach (var passwordHistory in lastTwoPasswords)
            {
                if (PasswordHasher.VerifyHashedPassword(identityUser, passwordHistory.HashedPassword, newPassword) == PasswordVerificationResult.Success)
                {
                    return IdentityResult.Failed(new IdentityError { Description = "You cannot reuse your last two passwords." });
                }
            }

            // Enforce minimum password age (e.g., 2 min for testing)
            if (userFromDb.PasswordLastChanged.HasValue && DateTime.UtcNow - userFromDb.PasswordLastChanged.Value < TimeSpan.FromMinutes(2))
            {
                return IdentityResult.Failed(new IdentityError { Description = "You cannot change your password more than once every 2 minutes." });
            }

            // Enforce maximum password age (e.g., 3 min for testing)
            if (userFromDb.PasswordLastChanged.HasValue && DateTime.UtcNow - userFromDb.PasswordLastChanged.Value > TimeSpan.FromMinutes(3))
            {
                return await ChangePasswordAsync(identityUser, oldPassword, newPassword);
            }

            // Proceed with password change
            var result = await ChangePasswordAsync(identityUser, oldPassword, newPassword);
            if (result.Succeeded)
            {
                _logger.LogInformation("Adding new password history for user {UserId} at {Time}.", userFromDb.UserID, DateTime.UtcNow);

                // Update password change timestamp in User entity
                userFromDb.PasswordLastChanged = DateTime.UtcNow;
                _dbContext.Entry(userFromDb).Property(u => u.PasswordLastChanged).IsModified = true;

                // Add the new password to the history
                _dbContext.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = userFromDb.UserID.ToString(),  // Convert UserID (Guid) to string for storage in PasswordHistories
                    HashedPassword = PasswordHasher.HashPassword(identityUser, newPassword),
                    CreatedAt = DateTime.UtcNow
                });

                await _dbContext.SaveChangesAsync();

        _logger.LogInformation("Password history for user {UserId} saved successfully at {Time}.", userFromDb.UserID, DateTime.UtcNow);
            }

            return result;
        }

    }
}
