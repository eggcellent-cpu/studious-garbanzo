using FreshFarmMarket.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FreshFarmMarket.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<CustomIdentityUser> _signInManager;

        public LogoutModel(SignInManager<CustomIdentityUser> signInManager)
        {
            _signInManager = signInManager;
        }

        // Handles logging out when the user presses "Log Out"
        public async Task<IActionResult> OnPostLogoutAsync()
        {
            await _signInManager.SignOutAsync(); // Sign out the user
            HttpContext.Session.Clear(); // Clear session data
            Response.Cookies.Delete("AuthToken"); // Delete the AuthToken cookie
            Response.Cookies.Delete("MyCookieAuth"); // Delete the MyCookieAuth cookie
            return RedirectToPage("/Login"); // Redirect to the Login page
        }

        // Handles if the user presses "Continue Session" (does nothing and redirects back)
        public IActionResult OnPostDontLogoutAsync()
        {
            return RedirectToPage("/Index"); // Redirect back to the home page
        }

        // Handles logout on a GET request (useful for direct logout links)
        public async Task<IActionResult> OnGetAsync()
        {
            await _signInManager.SignOutAsync(); // Sign out the user
            HttpContext.Session.Clear(); // Clear session data
            Response.Cookies.Delete("AuthToken"); // Delete AuthToken cookie
            Response.Cookies.Delete("MyCookieAuth"); // Delete MyCookieAuth cookie
            return RedirectToPage("/Login"); // Redirect to the Login page
        }
    }
}
