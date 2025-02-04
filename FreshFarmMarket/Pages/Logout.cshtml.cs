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

        // Handles logging out when the user presses "Log Out"
        public async Task<IActionResult> OnPostLogoutAsync()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value; // Get the user ID
            if (!string.IsNullOrEmpty(userId))
            {
                Console.WriteLine($"Attempting to log logout for user: {userId}");
                _logger.LogInformation($"Attempting to log logout for user: {userId}");

                // Log the logout activity
                await _auditLogService.LogActivityAsync(userId, "Logout",
                    $"Successful logout from IP: {HttpContext.Connection.RemoteIpAddress}");

                Console.WriteLine("Logout logged successfully.");
                _logger.LogInformation("Logout logged successfully.");
            }
            else
            {
                Console.WriteLine("User ID is null, cannot log logout activity.");
                _logger.LogWarning("User ID is null, cannot log logout activity.");
            }

            await _signInManager.SignOutAsync(); // Sign out the user
            HttpContext.Session.Clear(); // Clear session data
            Response.Cookies.Delete("AuthToken"); // Delete the AuthToken cookie
            Response.Cookies.Delete("MyCookieAuth"); // Delete the MyCookieAuth cookie
            Response.Cookies.Delete(".AspNetCore.Session"); // Delete the session cookie
            return RedirectToPage("/Login"); // Redirect to the Login page
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userId))
            {
                await _auditLogService.LogActivityAsync(userId, "Logout",
                    $"Successful logout from IP: {HttpContext.Connection.RemoteIpAddress}");
            }

            await _signInManager.SignOutAsync(); // Sign out the user
            HttpContext.Session.Clear(); // Clear session data
            Response.Cookies.Delete("AuthToken"); // Delete AuthToken cookie
            Response.Cookies.Delete("MyCookieAuth"); // Delete MyCookieAuth cookie
            Response.Cookies.Delete(".AspNetCore.Session"); // Delete the session cookie
            return RedirectToPage("/Login"); // Redirect to the Login page
        }
    }
}