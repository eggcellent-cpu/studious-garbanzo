using FreshFarmMarket.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using FreshFarmMarket.Model;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;
using FreshFarmMarket.Services.EncryptionService

namespace FreshFarmMarket.Pages
{
    public class RegisterModel : PageModel
    {
        private UserManager<CustomIdentityUser> userManager { get; }
        private SignInManager<CustomIdentityUser> signInManager { get; }
        private readonly ILogger<RegisterModel> _logger;
        private readonly MyAuthDbContext _dbContext;

        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(UserManager<CustomIdentityUser> userManager, SignInManager<CustomIdentityUser> signInManager, ILogger<RegisterModel> logger, MyAuthDbContext dbContext)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            _logger = logger;
            _dbContext = dbContext;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Photo validation
            if (RModel.Photo == null || RModel.Photo.Length == 0)
            {
                ModelState.AddModelError("Photo", "Photo is required.");
            }
            else
            {
                var fileName = RModel.Photo.FileName;
                var fileExtension = Path.GetExtension(fileName);
                _logger.LogInformation($"Uploaded File Name: {fileName}");
                _logger.LogInformation($"File Extension: {fileExtension}");

                const long MaxFileSize = 10 * 1024 * 1024; // 10 MB
                if (RModel.Photo.Length > MaxFileSize)
                {
                    ModelState.AddModelError("Photo", "The file is too large. Maximum size is 10 MB.");
                }

                if (!Regex.IsMatch(fileExtension, @"\.(jpg|jpeg)$", RegexOptions.IgnoreCase))
                {
                    ModelState.AddModelError("Photo", "Only JPG files are allowed.");
                }
                else if (!RModel.Photo.ContentType.StartsWith("image/jpeg", StringComparison.OrdinalIgnoreCase))
                {
                    ModelState.AddModelError("Photo", "Invalid file type. Only JPG files are allowed.");
                }
            }

            // Check if email already exists
            var existingUser = await userManager.FindByEmailAsync(RModel.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "This email address is already in use.");
            }

            if (ModelState.IsValid)
            {
                // Create a new User object
                var user = new CustomIdentityUser
                {
                    UserName = RModel.Email,
                    Email = RModel.Email,
                    PhoneNumber = RModel.MobileNo,
                    FullName = RModel.FullName,
                    Gender = RModel.Gender,
                    DeliveryAddress = RModel.DeliveryAddress,
                    AboutMe = RModel.AboutMe,
                    CreditCardNo = Encrypt(RModel.CreditCardNo) // Store encrypted credit card number
                };

                // Handle photo upload
                if (RModel.Photo != null)
                {
                    var uniqueFileName = Guid.NewGuid().ToString() + Path.GetExtension(RModel.Photo.FileName);
                    var uploadPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");

                    if (!Directory.Exists(uploadPath))
                    {
                        Directory.CreateDirectory(uploadPath);
                    }

                    var filePath = Path.Combine(uploadPath, uniqueFileName);
                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        await RModel.Photo.CopyToAsync(fileStream);
                    }

                    user.PhotoPath = "/uploads/" + uniqueFileName; // Store relative file path
                }

                // Create user in Identity (this hashes the password internally)
                var result = await userManager.CreateAsync(user, RModel.Password);

                if (result.Succeeded)
                {
                    await signInManager.SignInAsync(user, false);

                    // Save additional user info to the database
                    var newUser = new User
                    {
                        UserID = Guid.NewGuid(),
                        FullName = RModel.FullName,
                        Password = user.PasswordHash, // Store the hashed password from Identity
                        Email = RModel.Email,
                        CreditCardNo = RModel.CreditCardNo, // Store plain text for database (if required)
                        Gender = RModel.Gender,
                        MobileNo = RModel.MobileNo,
                        DeliveryAddress = RModel.DeliveryAddress,
                        AboutMe = RModel.AboutMe,
                        PhotoPath = user.PhotoPath // Store photo path
                    };

                    // Save user info to your own database (not Identity)
                    _dbContext.Users.Add(newUser);
                    await _dbContext.SaveChangesAsync();

                    return RedirectToPage("Index");
                }

                // Handle Identity errors
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            return Page();
        }
    }
}