using FreshFarmMarket.Model;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<CustomIdentityUser> _userManager;
        private readonly SignInManager<CustomIdentityUser> _signInManager;
        private readonly ILogger<ChangePasswordModel> _logger;
        private readonly MyAuthDbContext _dbContext;

        public ChangePasswordModel(UserManager<CustomIdentityUser> userManager, SignInManager<CustomIdentityUser> signInManager, ILogger<ChangePasswordModel> logger, MyAuthDbContext dbContext)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _dbContext = dbContext;
        }

        [BindProperty]
        [Required(ErrorMessage = "Current password is required.")]
        [DataType(DataType.Password)]
        public string OldPassword { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "New password is required.")]
        [StringLength(100, ErrorMessage = "Password must be at least {2} characters long.", MinimumLength = 12)]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$",
            ErrorMessage = "Password must be at least 12 characters long, including an uppercase letter, a lowercase letter, a number, and a special character.")]
        public string NewPassword { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Confirm password is required.")]
        [DataType(DataType.Password)]
        [Compare(nameof(NewPassword), ErrorMessage = "Confirm password does not match.")]
        public string ConfirmPassword { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!User.Identity.IsAuthenticated)
            {
                _logger.LogWarning("User is not authenticated. Redirecting to Login.");
                return RedirectToPage("/Login");
            }

            _logger.LogInformation("ChangePassword OnPostAsync triggered. Attempting to change password for user {UserName}", User.Identity.Name);

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogWarning("User not found for username {UserName}. Redirecting to Login.", User.Identity.Name);
                return RedirectToPage("/Login");
            }

            _logger.LogInformation("User found: {UserName}. Attempting to change password.", user.UserName);

            // Ensure new password is not the same as old password
            var passwordCheck = await _userManager.CheckPasswordAsync(user, OldPassword);
            if (!passwordCheck)
            {
                _logger.LogError("Incorrect current password for user {UserName}.", user.UserName);
                ModelState.AddModelError(string.Empty, "Incorrect current password.");
                return Page();
            }

            if (OldPassword == NewPassword)
            {
                _logger.LogError("New password must be different from the old password for user {UserName}.", user.UserName);
                ModelState.AddModelError(string.Empty, "New password cannot be the same as the old password.");
                return Page();
            }

            // **Check Password History - Last 2 Passwords**
            var lastTwoPasswords = _dbContext.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(2)
                .Select(ph => ph.HashedPassword)
                .ToList();

            foreach (var oldPasswordHash in lastTwoPasswords)
            {
                var passwordMatch = _userManager.PasswordHasher.VerifyHashedPassword(user, oldPasswordHash, NewPassword);
                if (passwordMatch == PasswordVerificationResult.Success)
                {
                    _logger.LogError("New password must not match the last two used passwords for user {UserName}.", user.UserName);
                    ModelState.AddModelError(string.Empty, "You cannot reuse your last two passwords. Please choose a different password.");
                    return Page();
                }
            }

            var result = await _userManager.ChangePasswordAsync(user, OldPassword, NewPassword);
            if (!result.Succeeded)
            {
                _logger.LogError("Password change failed for user {UserName}. Errors: {Errors}", user.UserName, string.Join(", ", result.Errors.Select(e => e.Description)));
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return Page();
            }

            _logger.LogInformation("Password changed successfully for user {UserName}. Signing out and back in.", user.UserName);

            // Add the new password to the PasswordHistory table
            var passwordHistory = new PasswordHistory
            {
                UserId = user.Id,
                HashedPassword = user.PasswordHash, // Assuming PasswordHash is the hashed password
                CreatedAt = DateTime.UtcNow
            };

            _dbContext.PasswordHistories.Add(passwordHistory);

            // **Ensure only last 2 passwords are kept**
            var passwordHistoryList = _dbContext.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .ToList();

            if (passwordHistoryList.Count > 2)
            {
                var passwordsToDelete = passwordHistoryList.Skip(2);
                _dbContext.PasswordHistories.RemoveRange(passwordsToDelete);
            }

            await _dbContext.SaveChangesAsync();


            TempData["SuccessMessage"] = "Password successfully changed!";
            TempData.Keep("SuccessMessage"); // Ensures it persists after redirect

            await _signInManager.SignOutAsync();
            await _signInManager.SignInAsync(user, isPersistent: false);

            return RedirectToPage("/Index");
        }
    }
}