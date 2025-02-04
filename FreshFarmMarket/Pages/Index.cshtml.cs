using FreshFarmMarket.Model;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FreshFarmMarket.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<CustomIdentityUser> _userManager;

        public IndexModel(ILogger<IndexModel> logger, UserManager<CustomIdentityUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        public void OnGet()
        {

        }

        public async Task<IActionResult> OnGetDisplayCreditCardAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            string decryptedCreditCard = EncryptionService.Decrypt(user.CreditCardNo);
            ViewData["CreditCardNo"] = decryptedCreditCard; // Display on the homepage
            return Page();
        }

    }
}
