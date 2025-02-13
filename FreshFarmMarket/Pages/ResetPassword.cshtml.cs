using FreshFarmMarket.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging; // Added for logging
using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<CustomIdentityUser> _userManager;
        private readonly MyAuthDbContext _dbContext;
        private readonly ILogger<ResetPasswordModel> _logger; // Logger instance

        [BindProperty]
        public ResetPassword ResetPassword { get; set; }

        public ResetPasswordModel(UserManager<CustomIdentityUser> userManager, MyAuthDbContext dbContext, ILogger<ResetPasswordModel> logger)
        {
            _userManager = userManager;
            _dbContext = dbContext;
            _logger = logger; // Initialize logger
        }

        public IActionResult OnGet(string email, string token)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
            {
                TempData["Error"] = "Invalid password reset token.";
                return RedirectToPage("/ForgotPassword");
            }

            ResetPassword = new ResetPassword
            {
                Email = email,
                Token = token
            };

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                TempData["Error"] = "Please correct the errors.";
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(ResetPassword.Email);
            if (user == null)
            {
                TempData["Error"] = "User not found.";
                return RedirectToPage("/ForgotPassword");
            }

            // Retrieve the last two password histories
            var passwordHistories = _dbContext.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(2)
                .ToList();

            foreach (var ph in passwordHistories)
            {
                if (_userManager.PasswordHasher.VerifyHashedPassword(user, ph.HashedPassword, ResetPassword.Password) == PasswordVerificationResult.Success)
                {
                    TempData["Error"] = "You cannot reuse your last two passwords.";
                    return Page();
                }
            }

            var resetResult = await _userManager.ResetPasswordAsync(user, ResetPassword.Token, ResetPassword.Password);
            if (resetResult.Succeeded)
            {
                // Add new password to the PasswordHistory table
                var passwordHistory = new PasswordHistory
                {
                    UserId = user.Id,
                    HashedPassword = user.PasswordHash, // Store hashed password
                    CreatedAt = DateTime.UtcNow
                };

                _dbContext.PasswordHistories.Add(passwordHistory);
                await _dbContext.SaveChangesAsync();

                // Ensure only last 2 passwords are kept
                var updatedPasswordHistories = _dbContext.PasswordHistories
                    .Where(ph => ph.UserId == user.Id)
                    .OrderByDescending(ph => ph.CreatedAt)
                    .ToList();

                if (updatedPasswordHistories.Count > 2)
                {
                    var passwordsToDelete = updatedPasswordHistories.Skip(2).ToList();
                    _dbContext.PasswordHistories.RemoveRange(passwordsToDelete);
                    await _dbContext.SaveChangesAsync();

                    _logger.LogInformation($"Deleted old passwords for user {user.Id}:");
                    foreach (var ph in passwordsToDelete)
                    {
                        _logger.LogInformation($"  - Password change for user {user.Id} at {ph.CreatedAt}");
                    }
                }



                // Log final password history
                var finalPasswordHistories = _dbContext.PasswordHistories
                    .Where(ph => ph.UserId == user.Id)
                    .OrderByDescending(ph => ph.CreatedAt)
                    .ToList();

                foreach (var ph in finalPasswordHistories)
                {
                    _logger.LogInformation($"  - Password change for user {user.Id} at {ph.CreatedAt}");
                }

                TempData["ResetMessage"] = "Password has been reset successfully.";
                return RedirectToPage("/Login");
            }

            // Handle specific errors
            foreach (var error in resetResult.Errors)
            {
                if (error.Code == "InvalidToken")
                {
                    TempData["Error"] = "The password reset link is invalid or has expired.";
                    return RedirectToPage("/ForgotPassword");
                }
            }

            TempData["Error"] = "There was an error resetting the password.";
            return Page();
        }
    }
}
