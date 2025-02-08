using FreshFarmMarket.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using FreshFarmMarket.ViewModels;

public class ChangePasswordModel : PageModel
{
    private readonly UserManager<CustomIdentityUser> _userManager;

    [BindProperty]
    public ChangePasswordViewModel ChangePasswordViewModel { get; set; }

    public ChangePasswordModel(UserManager<CustomIdentityUser> userManager)
    {
        _userManager = userManager;
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound("User not found.");
        }

        // Check if the new password is in the history
        if (await IsPasswordInHistory(user, ChangePasswordViewModel.NewPassword))
        {
            ModelState.AddModelError("NewPassword", "You cannot reuse your last 2 passwords.");
            return Page();
        }

        // Change the password
        var changePasswordResult = await _userManager.ChangePasswordAsync(user, ChangePasswordViewModel.OldPassword, ChangePasswordViewModel.NewPassword);
        if (!changePasswordResult.Succeeded)
        {
            foreach (var error in changePasswordResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return Page();
        }

        // Update password history
        var newPasswordHash = _userManager.PasswordHasher.HashPassword(user, ChangePasswordViewModel.NewPassword);
        await UpdatePasswordHistory(user, newPasswordHash);

        TempData["Success"] = "Your password has been changed successfully.";
        return RedirectToPage("/Index");
    }

    private async Task<bool> IsPasswordInHistory(CustomIdentityUser user, string newPassword)
    {
        foreach (var oldPasswordHash in user.PasswordHistory)
        {
            var result = _userManager.PasswordHasher.VerifyHashedPassword(user, oldPasswordHash, newPassword);
            if (result == PasswordVerificationResult.Success)
            {
                return true; // Password is in history
            }
        }
        return false; // Password is not in history
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
