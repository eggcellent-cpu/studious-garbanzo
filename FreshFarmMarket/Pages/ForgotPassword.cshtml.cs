using FreshFarmMarket.Model;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<CustomIdentityUser> _userManager;
        private readonly IEmailSender _emailSender;

        [BindProperty]
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        public string Email { get; set; }

        public ForgotPasswordModel(UserManager<CustomIdentityUser> userManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _emailSender = emailSender;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                TempData["Error"] = "Invalid email address.";
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                TempData["Error"] = "No user found with this email address.";
                return Page();
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = Url.Page(
                "/ResetPassword",
                pageHandler: null,
                values: new { token, email = Email },
                protocol: Request.Scheme);

            var emailBody = $@"
            <p>Hello,</p>
            <p>You requested a password reset. Click the link below to reset your password:</p>
            <p><a href='{callbackUrl}'>Reset Password</a></p>
            <p><strong>Note:</strong> This link is valid for <b>1 minutes</b>. If you did not request this, please ignore this email.</p>
            <p>FreshFarmMarket Team</p>"; 
            
            await _emailSender.SendEmailAsync(Email, "Password Reset", emailBody);

            TempData["Message"] = "Password reset link has been sent. Please check your email.";
            return RedirectToPage();
        }
    }

}
