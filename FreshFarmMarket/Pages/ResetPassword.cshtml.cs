using FreshFarmMarket.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using FreshFarmMarket.ViewModels;

public class ResetPasswordModel : PageModel
{
    private readonly UserManager<CustomIdentityUser> _userManager;

    [BindProperty]
    public ResetPasswordViewModel ResetPasswordViewModel { get; set; }

    public ResetPasswordModel(UserManager<CustomIdentityUser> userManager)
    {
        _userManager = userManager;
    }

    public void OnGet(string token, string email)
    {
        ResetPasswordViewModel = new ResetPasswordViewModel
        {
            Token = token,
            Email = email
        };
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(ResetPasswordViewModel.Email);
        if (user == null)
        {
            return NotFound("User not found.");
        }

        // Reset the password
        var resetPasswordResult = await _userManager.ResetPasswordAsync(user, ResetPasswordViewModel.Token, ResetPasswordViewModel.NewPassword);
        if (!resetPasswordResult.Succeeded)
        {
            foreach (var error in resetPasswordResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return Page();
        }

        // Update password history
        var newPasswordHash = _userManager.PasswordHasher.HashPassword(user, ResetPasswordViewModel.NewPassword);
        await UpdatePasswordHistory(user, newPasswordHash);

        TempData["Success"] = "Your password has been reset successfully.";
        return RedirectToPage("/Login");
    }

    private async Task UpdatePasswordHistory(CustomIdentityUser user, string newPasswordHash)
    {
        user.PasswordHistory.Insert(0, newPasswordHash); // Add new hash to the beginning
        if (user.PasswordHistory.Count > 2) // Keep only the last 2 passwords
        {
            user.PasswordHistory.RemoveAt(user.PasswordHistory.Count - 1);
        }
        await _userManager.UpdateAsync(user);
    }
}
