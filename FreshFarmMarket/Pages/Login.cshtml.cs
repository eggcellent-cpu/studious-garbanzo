using FreshFarmMarket.Model;
using FreshFarmMarket.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using FreshFarmMarket.Middleware;
using Ganss.Xss;
using FreshFarmMarket.Services;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace FreshFarmMarket.Pages
{
    public class LoginModel : PageModel
    {
        private readonly MyAuthDbContext _dbContext;
        private readonly ILogger<LoginModel> _logger;
        private readonly PasswordHasher<User> _passwordHasher = new();
        private readonly ReCaptchaService _reCaptchaService;
        private readonly string _recaptchaSecret;
        private readonly string _recaptchaVerificationUrl;
        private readonly SignInManager<CustomIdentityUser> _signInManager;
        private readonly UserManager<CustomIdentityUser> _userManager;
        private readonly AuditLogService _auditLogService;
        private readonly IEmailSender _emailSender;

        [BindProperty]
        public Login LModel { get; set; }

        public int RemainingAttempts { get; private set; }

        public LoginModel(MyAuthDbContext dbContext, ILogger<LoginModel> logger, ReCaptchaService reCaptchaService, IConfiguration configuration, SignInManager<CustomIdentityUser> signInManager, UserManager<CustomIdentityUser> userManager, AuditLogService auditLogService, IEmailSender emailSender)
        {
            _dbContext = dbContext;
            _logger = logger;
            _reCaptchaService = reCaptchaService;
            _recaptchaSecret = configuration["ReCaptchaSettings:SecretKey"];
            _recaptchaVerificationUrl = configuration["ReCaptchaSettings:VerificationUrl"];
            _signInManager = signInManager;
            _userManager = userManager;
            _auditLogService = auditLogService;
            _emailSender = emailSender;
        }

        public IActionResult OnGet()
        {
            Console.WriteLine($"User Identity: {HttpContext.User.Identity?.Name}");
            Console.WriteLine($"User Is Authenticated: {HttpContext.User.Identity?.IsAuthenticated}");

            var sessionAuthToken = HttpContext.Session.GetString("AuthToken");
            var cookieAuthToken = Request.Cookies["AuthToken"];
            var sessionExpireTime = HttpContext.Session.GetString("SessionExpireTime");

            // Check if session timeout has occurred
            if (string.IsNullOrEmpty(sessionExpireTime) || DateTime.UtcNow > DateTime.Parse(sessionExpireTime))
            {
                HttpContext.Session.Clear();
                Response.Cookies.Delete(".AspNetCore.Session"); // Delete the session cookie
                Response.Cookies.Delete("AuthToken");
                Response.Cookies.Delete("MyCookieAuth");
                if (!Request.Path.Value.EndsWith("/Login", StringComparison.OrdinalIgnoreCase))
                {
                    return RedirectToPage("/Login");
                }
            }

            if (string.IsNullOrEmpty(sessionAuthToken) || string.IsNullOrEmpty(cookieAuthToken) || sessionAuthToken != cookieAuthToken)
            {
                HttpContext.Session.Clear();
                Response.Cookies.Delete(".AspNetCore.Session"); // Delete the session cookie
                Response.Cookies.Delete("AuthToken");
                Response.Cookies.Delete("MyCookieAuth");

                if (!Request.Path.Value.EndsWith("/Login", StringComparison.OrdinalIgnoreCase))
                {
                    return RedirectToPage("/Login");
                }
            }

            return Page();
        }

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            _logger.LogInformation($"User Identity Before Login: {HttpContext.User.Identity?.Name}");
            Console.WriteLine($"User Is Authenticated Before Login: {HttpContext.User.Identity?.IsAuthenticated}");

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Verify reCAPTCHA token
            var recaptchaToken = Request.Form["recaptchaToken"];
            if (string.IsNullOrEmpty(recaptchaToken) ||
                !await _reCaptchaService.VerifyRecaptchaAsync(recaptchaToken, _recaptchaSecret, _recaptchaVerificationUrl))
            {
                _logger.LogWarning("reCAPTCHA validation failed for token {TokenHash}", GetHash(recaptchaToken));  // Log hashed value
                TempData["Error"] = "reCAPTCHA validation failed. Please try again.";
                return Page();
            }

            // Sanitize user input
            var sanitizer = new HtmlSanitizer();
            LModel.Email = sanitizer.Sanitize(LModel.Email);


            var user = await _userManager.FindByEmailAsync(LModel.Email);
            var userFromDb = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == LModel.Email);


            if (userFromDb == null)
            {
                TempData["Error"] = "Invalid email or password.";
                _logger.LogWarning("Login attempt failed: User not found for email {Email}", LModel.Email);

                return Page();
            }

            // Track the remaining attempts
            var maxFailedAttempts = 3;
            RemainingAttempts = maxFailedAttempts - userFromDb.FailedLoginAttempts;

            TempData["RemainingAttempts"] = RemainingAttempts;

            // Check for account lockout

            if (userFromDb.IsLocked && userFromDb.LastFailedLogin.HasValue)
            {
                var lockoutDuration = DateTime.UtcNow - userFromDb.LastFailedLogin.Value;

                if (lockoutDuration.TotalMinutes < 1)  // Assuming a 1-minute lockout duration
                {
                    TempData["Error"] = $"Your account is locked. Please try again in {1 - lockoutDuration.TotalMinutes:F0} minutes.";
                    _logger.LogWarning("Login attempt failed: Account locked for email {Email}", LModel.Email);
                    return Page();
                }
                else
                {
                    // Automatically unlock the account after lockout period has expired
                    userFromDb.IsLocked = false;
                    userFromDb.FailedLoginAttempts = 0;  // Reset failed attempts
                    await _dbContext.SaveChangesAsync();
                }
            }


            // Attempt to sign in the user
            var result = await _signInManager.PasswordSignInAsync(user, LModel.Password, false, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                // Reset failed login attempts on successful login
                userFromDb.FailedLoginAttempts = 0;
                userFromDb.LastFailedLogin = null;
                await _dbContext.SaveChangesAsync();

                var authToken = Guid.NewGuid().ToString();

                // Store session token in database for tracking multiple logins
                user.SessionToken = authToken;
                await _dbContext.SaveChangesAsync();

                HttpContext.Session.Clear(); // Prevent session fixation

                HttpContext.Session.SetString("AuthToken", authToken);
                HttpContext.Session.SetString("CurrentUser", user.Email);
                HttpContext.Session.SetString("SessionExpireTime", DateTime.UtcNow.AddSeconds(30).ToString());

                Response.Cookies.Append("AuthToken", authToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddSeconds(30)
                });

                Response.Cookies.Append("MyCookieAuth", authToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = false,  // Set to false for local development or true for production
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddSeconds(30)
                });

                HttpContext.Session.SetString("CurrentUser", user.Email);
                HttpContext.Session.SetString("SessionExpireTime", DateTime.UtcNow.AddMinutes(30).ToString());


                _logger.LogInformation("User {Email} logged in successfully", LModel.Email);

                await _auditLogService.LogActivityAsync(user.Id, "Login", $"Successful login from IP: {HttpContext.Connection.RemoteIpAddress}");


                return RedirectToPage("/Index");
            }
            else if (result.IsLockedOut)
            {
                TempData["Error"] = "Your account is locked due to multiple failed login attempts. Please contact support.";
                _logger.LogWarning("Login attempt failed: Account locked for email {Email}", LModel.Email);
                return Page();
            }
            else
            {
                // Increment failed login attempts since credentials are incorrect
                userFromDb.FailedLoginAttempts++;
                userFromDb.LastFailedLogin = DateTime.UtcNow;

                if (userFromDb.FailedLoginAttempts >= maxFailedAttempts)
                {
                    userFromDb.IsLocked = true;
                    TempData["Error"] = "Your account has been locked due to multiple failed login attempts. Please try again later.";
                }
                else
                {
                    TempData["Error"] = $"Invalid email or password. You have {maxFailedAttempts - userFromDb.FailedLoginAttempts} attempts remaining.";
                }

                // Update the user record
                await _dbContext.SaveChangesAsync();  // Save failed attempts increment

                TempData["Error"] = "Invalid email or password.";
                _logger.LogWarning("Login attempt failed: Invalid credentials for email {Email}", LModel.Email);
                return Page();
            }
        }

        // Forget and Reset Password
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPassword forgotPassword)
        {
            if (!ModelState.IsValid)
            {
                TempData["Message"] = "Invalid input.";
                return RedirectToPage("/ForgotPassword");
            }

            var user = await _userManager.FindByEmailAsync(forgotPassword.Email!);
            if (user == null)
            {
                TempData["Message"] = "User not found.";
                return RedirectToPage("/ForgotPassword");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var param = new Dictionary<string, string?>
            {
                { "token", token },
                { "email", forgotPassword.Email! }
            };

            var callbackUrl = QueryHelpers.AddQueryString(forgotPassword.ClientUrl!, param);
            var emailBody = $"Click <a href='{callbackUrl}'>here</a> to reset your password.";

            await _emailSender.SendEmailAsync(forgotPassword.Email!, "Reset Password", emailBody);

            TempData["Message"] = "Password reset link has been sent.";
            return RedirectToPage("/ForgotPassword");  // Or another success page
        }


        private string GetHash(string input)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(hashBytes); // You can return the hashed value here
            }
        }
    }
}
