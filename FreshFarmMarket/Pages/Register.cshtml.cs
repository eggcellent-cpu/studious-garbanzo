using FreshFarmMarket.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using FreshFarmMarket.Model;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;
using FreshFarmMarket.Services;

namespace FreshFarmMarket.Pages
{
    public class RegisterModel : PageModel
    {
        private UserManager<CustomIdentityUser> userManager { get; }
        private SignInManager<CustomIdentityUser> signInManager { get; }
        private readonly ILogger<RegisterModel> _logger;
        private readonly MyAuthDbContext _dbContext;
        private readonly EncryptionService _encryptionService;


        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(UserManager<CustomIdentityUser> userManager, SignInManager<CustomIdentityUser> signInManager, ILogger<RegisterModel> logger, MyAuthDbContext dbContext, EncryptionService encryptionService)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            _logger = logger;
            _dbContext = dbContext;
            _encryptionService = encryptionService;

        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page(); // Return the same page to show validation errors
            }

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

            // Validate Credit Card Number (Must be exactly 16 digits)
            if (!Regex.IsMatch(RModel.CreditCardNo, @"^\d{16}$"))
            {
                ModelState.AddModelError("CreditCardNo", "Credit card number must be exactly 16 digits.");
            }

            // Validate Delivery Address (Max 250 characters)
            if (RModel.DeliveryAddress.Length > 250)
            {
                ModelState.AddModelError("DeliveryAddress", "Delivery address cannot exceed 250 characters.");
            }

            // Check if email already exists
            var existingUser = await userManager.FindByEmailAsync(RModel.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "This email address is already in use.");
            }

            if (ModelState.IsValid)
            {
                // Encrypt sensitive data
                string encryptedCreditCard = _encryptionService.Encrypt(RModel.CreditCardNo);
                string encryptedPhoneNumber = _encryptionService.Encrypt(RModel.MobileNo);
                string encryptedDeliveryAddress = _encryptionService.Encrypt(RModel.DeliveryAddress);

                // Create a new User object
                var user = new CustomIdentityUser
                {
                    UserName = RModel.Email,
                    Email = RModel.Email,
                    PhoneNumber = encryptedPhoneNumber,
                    FullName = RModel.FullName,
                    Gender = RModel.Gender,
                    DeliveryAddress = encryptedDeliveryAddress,
                    AboutMe = RModel.AboutMe,
                    CreditCardNo = encryptedCreditCard // Store encrypted credit card number
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

                // Create user in Identity 
                var result = await userManager.CreateAsync(user, RModel.Password);

                if (result.Succeeded)
                {
                    // Save password history (add to PasswordHistories table)
                    _dbContext.PasswordHistories.Add(new PasswordHistory
                    {
                        UserId = user.Id,  // Store the user ID
                        HashedPassword = user.PasswordHash, // Save the hashed password
                        CreatedAt = DateTime.UtcNow // Timestamp
                    });

                    await _dbContext.SaveChangesAsync();  // Save changes to the database
                    _logger.LogInformation("Password history added for new user {UserId}.", user.Id);


                    // Sign in the user
                    await signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation("User signed in successfully.");

                    // Log audit entry
                    try
                    {
                        var auditLog = new AuditLog
                        {
                            UserId = user.Id,
                            Activity = "Registration",
                            Timestamp = DateTime.UtcNow,
                            Details = "User registered successfully."
                        };

                        _dbContext.AuditLogs.Add(auditLog);
                        await _dbContext.SaveChangesAsync();
                        _logger.LogInformation("Audit log entry created successfully.");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to log audit entry.");
                    }

                    // Save additional user info to the database
                    var newUser = new User
                    {
                        UserID = Guid.NewGuid(),
                        FullName = RModel.FullName,
                        Password = user.PasswordHash, // Store the hashed password from Identity
                        Email = RModel.Email,
                        CreditCardNo = encryptedCreditCard, // Store plain text for database (if required)
                        Gender = RModel.Gender,
                        MobileNo = encryptedPhoneNumber,
                        DeliveryAddress = encryptedDeliveryAddress,
                        AboutMe = RModel.AboutMe,
                        PhotoPath = user.PhotoPath // Store photo path
                    };

                    // Save user info to your own database (not Identity)
                    _dbContext.Users.Add(newUser);
                    await _dbContext.SaveChangesAsync();

                    // Set success message
                    TempData["SuccessMessage"] = "Registration successful! Please log in.";
                    return RedirectToPage("Login");
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