using FreshFarmMarket.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<CustomIdentityUser> _userManager;

        [BindProperty]
        public ResetPassword ResetPassword { get; set; }

        public ResetPasswordModel(UserManager<CustomIdentityUser> userManager)
        {
            _userManager = userManager;
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

            var resetResult = await _userManager.ResetPasswordAsync(user, ResetPassword.Token, ResetPassword.Password);
            if (resetResult.Succeeded)
            {
                TempData["Message"] = "Password has been reset successfully.";
                return RedirectToPage("/Login"); // Redirect to Login page after successful reset
            }
            // Handle specific errors
            foreach (var error in resetResult.Errors)
            {
                if (error.Code == "InvalidToken")
                {
                    TempData["Error"] = "The password reset link is invalid or has expired.";
                    return RedirectToPage("/ForgotPassword"); // Redirect user to request a new reset link
                }
            }

            TempData["Error"] = "There was an error resetting the password.";
            return Page();
        }
    }
}
