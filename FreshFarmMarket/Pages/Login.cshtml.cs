using FreshFarmMarket.Model;
using FreshFarmMarket.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using FreshFarmMarket.Middleware;
using Ganss.Xss;
using FreshFarmMarket.Services;

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

        [BindProperty]
        public Login LModel { get; set; }

        public int RemainingAttempts { get; private set; }

        public LoginModel(MyAuthDbContext dbContext, ILogger<LoginModel> logger, ReCaptchaService reCaptchaService, IConfiguration configuration, SignInManager<CustomIdentityUser> signInManager, UserManager<CustomIdentityUser> userManager, AuditLogService auditLogService)
        {
            _dbContext = dbContext;
            _logger = logger;
            _reCaptchaService = reCaptchaService;
            _recaptchaSecret = configuration["ReCaptchaSettings:SecretKey"];
            _recaptchaVerificationUrl = configuration["ReCaptchaSettings:VerificationUrl"];
            _signInManager = signInManager;
            _userManager = userManager;
            _auditLogService = auditLogService;
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
                _logger.LogWarning("reCAPTCHA validation failed for token {Token}", recaptchaToken);
                TempData["Error"] = "reCAPTCHA validation failed. Please try again.";
                return Page();
            }

            // Sanitize user input
            var sanitizer = new HtmlSanitizer();
            LModel.Email = sanitizer.Sanitize(LModel.Email);

            var user = await _userManager.FindByEmailAsync(LModel.Email);
            if (user == null)
            {
                TempData["Error"] = "Invalid email or password.";
                _logger.LogWarning("Login attempt failed: User not found for email {Email}", LModel.Email);
                return Page();
            }

            // Check for account lockout
            if (user.LockoutEnabled && user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTimeOffset.UtcNow)
            {
                TempData["Error"] = "Your account is locked due to multiple failed login attempts. Please contact support.";
                _logger.LogWarning("Login attempt failed: Account locked for email {Email}", LModel.Email);
                return Page();
            }

            // Attempt to sign in the user
            var result = await _signInManager.PasswordSignInAsync(user, LModel.Password, false, lockoutOnFailure: true);
            if (result.Succeeded)
            {
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
                TempData["Error"] = "Invalid email or password.";
                _logger.LogWarning("Login attempt failed: Invalid credentials for email {Email}", LModel.Email);
                return Page();
            }
        }
    }
}
