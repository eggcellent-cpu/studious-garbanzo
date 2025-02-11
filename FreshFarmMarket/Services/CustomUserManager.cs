using FreshFarmMarket.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FreshFarmMarket.Services
{
    public class CustomUserManager : UserManager<CustomIdentityUser>
    {
        private readonly TimeSpan minPasswordAge = TimeSpan.FromMinutes(5); // Cannot change within 5 mins
        private readonly TimeSpan maxPasswordAge = TimeSpan.FromDays(30); // Must change after 30 days

        public CustomUserManager(IUserStore<CustomIdentityUser> store, IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<CustomIdentityUser> passwordHasher, IEnumerable<IUserValidator<CustomIdentityUser>> userValidators,
            IEnumerable<IPasswordValidator<CustomIdentityUser>> passwordValidators, ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<CustomIdentityUser>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
        }

        public async Task<IdentityResult> ChangePasswordWithPolicyAsync(CustomIdentityUser user, string currentPassword, string newPassword)
        {
            if ((DateTime.UtcNow - user.LastPasswordChange) < minPasswordAge)
            {
                return IdentityResult.Failed(new IdentityError { Description = "You must wait before changing your password again." });
            }

            if (user.PasswordHistory.Take(2).Any(p => PasswordHasher.VerifyHashedPassword(user, p, newPassword) == PasswordVerificationResult.Success))
            {
                return IdentityResult.Failed(new IdentityError { Description = "You cannot reuse your last 2 passwords." });
            }

            var result = await base.ChangePasswordAsync(user, currentPassword, newPassword);
            if (result.Succeeded)
            {
                if (user.PasswordHistory.Count >= 2)
                    user.PasswordHistory.RemoveAt(0); // Keep only last 2 passwords

                user.PasswordHistory.Add(PasswordHasher.HashPassword(user, newPassword));
                user.LastPasswordChange = DateTime.UtcNow;

                await UpdateAsync(user);
            }

            return result;
        }

        public bool IsPasswordExpired(CustomIdentityUser user)
        {
            return (DateTime.UtcNow - user.LastPasswordChange) > maxPasswordAge;
        }
    }
}
