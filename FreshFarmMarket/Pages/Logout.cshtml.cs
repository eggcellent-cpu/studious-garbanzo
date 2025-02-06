using FreshFarmMarket.Model;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace FreshFarmMarket.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<CustomIdentityUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;
        private readonly AuditLogService _auditLogService;
        private readonly UserManager<CustomIdentityUser> _userManager;

        public LogoutModel(SignInManager<CustomIdentityUser> signInManager, ILogger<LogoutModel> logger, AuditLogService auditLogService, UserManager<CustomIdentityUser> userManager)
        {
            _signInManager = signInManager;
            _logger = logger;
            _auditLogService = auditLogService;
            _userManager = userManager;
        }

        // Logout Handler (For Both Manual Logout & Session Expiry)
        public async Task<IActionResult> OnGetAsync(bool sessionExpired = false)
        {
            // Clear TempData for remaining attempts
            TempData.Remove("RemainingAttempts");

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (!string.IsNullOrEmpty(userId))
            {
                await _auditLogService.LogActivityAsync(userId, "Logout",
                    $"User logged out from IP: {HttpContext.Connection.RemoteIpAddress}");
                _logger.LogInformation($"User {userId} logged out.");
            }

            await _signInManager.SignOutAsync(); // Sign out the user
            HttpContext.Session.Clear(); // Clear session data

            // Delete authentication & session cookies
            Response.Cookies.Delete("AuthToken");
            Response.Cookies.Delete("MyCookieAuth");
            Response.Cookies.Delete(".AspNetCore.Session");

            // Show session expiration message if applicable
            if (sessionExpired)
            {
                TempData["SessionExpired"] = "Your session has expired. Please log in again.";
            }

            return RedirectToPage("/Login"); // Redirect to login page
        }
    }
}
