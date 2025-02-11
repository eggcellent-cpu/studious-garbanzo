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
            ILogger<UserManager<CustomIdentityUser>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            _dbContext = dbContext;
        }

        public async Task<IdentityResult> ChangePasswordWithPolicyAsync(CustomIdentityUser user, string oldPassword, string newPassword)
        {
            if (user == null)
            {
                return IdentityResult.Failed(new IdentityError { Description = "User cannot be null." });
            }

            // Retrieve User entity from the database
            var userFromDb = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == user.Email);
            if (userFromDb == null)
            {
                return IdentityResult.Failed(new IdentityError { Description = "User not found." });
            }

            var identityUser = await _dbContext.Users.OfType<CustomIdentityUser>().FirstOrDefaultAsync(u => u.Email == user.Email) ?? user;


            // Check password history
            var lastTwoPasswords = await _dbContext.PasswordHistories
                .AsNoTracking()
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(2)
                .ToListAsync();

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
                // Update password change timestamp in User entity
                userFromDb.PasswordLastChanged = DateTime.UtcNow;
                _dbContext.Entry(userFromDb).Property(u => u.PasswordLastChanged).IsModified = true;

                // Add the new password to the history
                _dbContext.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = identityUser.Id,
                    HashedPassword = PasswordHasher.HashPassword(identityUser, newPassword),
                    CreatedAt = DateTime.UtcNow
                });

                await _dbContext.SaveChangesAsync();
            }

            return result;
        }
    }
}
