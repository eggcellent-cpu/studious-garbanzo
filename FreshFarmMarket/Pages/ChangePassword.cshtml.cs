using FreshFarmMarket.Model;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FreshFarmMarket.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<CustomIdentityUser> _userManager;
        private readonly SignInManager<CustomIdentityUser> _signInManager;
        private readonly ILogger<ChangePasswordModel> _logger;  // Inject ILogger

        public ChangePasswordModel(UserManager<CustomIdentityUser> userManager, SignInManager<CustomIdentityUser> signInManager, ILogger<ChangePasswordModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;  // Assign the injected logger
        }

        [BindProperty]
        public string OldPassword { get; set; }

        [BindProperty]
        public string NewPassword { get; set; }

        public bool Expired { get; private set; }

        public async Task<IActionResult> OnGetAsync(bool expired = false)
        {
            Expired = expired;
            _logger.LogInformation("ChangePassword OnGetAsync triggered. Expired: {Expired}", expired); // Log when the page is accessed
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Check if the user is authenticated
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

            // Log the success of the password change
            _logger.LogInformation("Password changed successfully for user {UserName}. Signing out and back in.", user.UserName);

            // Sign out the user and sign them back in
            await _signInManager.SignOutAsync();
            await _signInManager.SignInAsync(user, isPersistent: false);

            return RedirectToPage("/Index");
        }
    }
}
