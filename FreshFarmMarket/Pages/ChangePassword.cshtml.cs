using FreshFarmMarket.Model;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FreshFarmMarket.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly CustomUserManager _userManager;
        private readonly SignInManager<CustomIdentityUser> _signInManager;

        public ChangePasswordModel(CustomUserManager userManager, SignInManager<CustomIdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [BindProperty]
        public string OldPassword { get; set; }

        [BindProperty]
        public string NewPassword { get; set; }

        public bool Expired { get; private set; }

        public async Task<IActionResult> OnGetAsync(bool expired = false)
        {
            Expired = expired;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            var result = await _userManager.ChangePasswordWithPolicyAsync(user, OldPassword, NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return Page();
            }

            return RedirectToPage("/Index");
        }
    }
}
