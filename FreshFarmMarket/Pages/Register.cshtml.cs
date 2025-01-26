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

                // Create user in Identity
                var result = await userManager.CreateAsync(user, RModel.Password);

                if (result.Succeeded)
                {
                    await signInManager.SignInAsync(user, false);

                    // Save additional user info to the database
                    var newUser = new User
                    {
                        UserID = Guid.NewGuid(),
                        FullName = RModel.FullName,
                        Password = RModel.Password,
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

        private string Encrypt(string data)
        {
            using (var aes = Aes.Create())
            {
                aes.GenerateKey();
                aes.GenerateIV();

                byte[] key = aes.Key;
                byte[] iv = aes.IV;

                using (var encryptor = aes.CreateEncryptor(key, iv))
                {
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            using (var sw = new StreamWriter(cs))
                            {
                                sw.Write(data);
                            }
                        }

                        byte[] encryptedData = ms.ToArray();
                        string encryptedText = Convert.ToBase64String(encryptedData);
                        string keyIvData = Convert.ToBase64String(key) + ":" + Convert.ToBase64String(iv);
                        return $"{keyIvData}:{encryptedText}";
                    }
                }
            }
        }

        private string Decrypt(string encryptedDataWithKeyIv)
        {
            string[] parts = encryptedDataWithKeyIv.Split(':');
            string base64Key = parts[0];
            string base64Iv = parts[1];
            string encryptedText = parts[2];

            byte[] key = Convert.FromBase64String(base64Key);
            byte[] iv = Convert.FromBase64String(base64Iv);
            byte[] encryptedData = Convert.FromBase64String(encryptedText);

            using (var aes = Aes.Create())
            {
                using (var decryptor = aes.CreateDecryptor(key, iv))
                {
                    using (var ms = new MemoryStream(encryptedData))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var sr = new StreamReader(cs))
                            {
                                return sr.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }

    }
}
