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
using Ganss.Xss; // For input sanitization

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

        [BindProperty]
        public Login LModel { get; set; }

        public int RemainingAttempts { get; private set; }

        public LoginModel(MyAuthDbContext dbContext, ILogger<LoginModel> logger, ReCaptchaService reCaptchaService, IConfiguration configuration, SignInManager<CustomIdentityUser> signInManager, UserManager<CustomIdentityUser> userManager)
        {
            _dbContext = dbContext;
            _logger = logger;
            _reCaptchaService = reCaptchaService;
            _recaptchaSecret = configuration["ReCaptchaSettings:SecretKey"];
            _recaptchaVerificationUrl = configuration["ReCaptchaSettings:VerificationUrl"];
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public IActionResult OnGet()
        {
            var sessionAuthToken = HttpContext.Session.GetString("AuthToken");
            var cookieAuthToken = Request.Cookies["AuthToken"];

            if (string.IsNullOrEmpty(sessionAuthToken) ||
                string.IsNullOrEmpty(cookieAuthToken) ||
                sessionAuthToken != cookieAuthToken)
            {
                // Clear session and cookies if the tokens are mismatched or missing
                HttpContext.Session.Clear();
                Response.Cookies.Delete("AuthToken");

                // Redirect to login page
                if (!HttpContext.Request.Path.Value.EndsWith("Login", StringComparison.OrdinalIgnoreCase))
                {
                    return RedirectToPage("Login");
                }
            }


            return Page();
        }


        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                var currentUser = await _userManager.FindByEmailAsync(LModel.Email);
                if (currentUser != null)
                {
                    var result = await _signInManager.PasswordSignInAsync(currentUser, LModel.Password, false, false);
                    if (result.Succeeded)
                    {
                        return RedirectToPage("/Index");  // Redirect to home page or another protected page
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "User not found.");
                }
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

            var user = await _dbContext.Users
                .FirstOrDefaultAsync(u => u.Email.ToLower() == LModel.Email.ToLower());

            // Check for account lockout
            if (user?.IsLocked == true && user.LastFailedLogin.HasValue &&
                user.LastFailedLogin.Value.AddMinutes(30) < DateTime.UtcNow)
            {
                user.FailedLoginAttempts = 0;
                user.IsLocked = false;
                user.LastFailedLogin = null;
                await _dbContext.SaveChangesAsync();
            }

            if (user == null)
            {
                TempData["Error"] = "Invalid email or password.";
                _logger.LogWarning("Login attempt failed: User not found for email {Email}", LModel.Email);
                return Page();
            }

            var passwordVerificationResult = _passwordHasher.VerifyHashedPassword(user, user.Password, LModel.Password);
            if (passwordVerificationResult != PasswordVerificationResult.Success)
            {
                TempData["Error"] = "Invalid email or password.";
                _logger.LogWarning("Password verification failed for email {Email}", LModel.Email);
                await IncrementLoginFailure(user);

                // Display remaining attempts
                RemainingAttempts = 3 - user.FailedLoginAttempts;
                TempData["RemainingAttempts"] = RemainingAttempts;

                return Page();
            }

            if (user.IsLocked)
            {
                TempData["Error"] = "Your account is locked due to multiple failed login attempts. Please contact support.";
                _logger.LogWarning("Login attempt failed: Account locked for email {Email}", LModel.Email);
                return Page();
            }

            user.FailedLoginAttempts = 0; // Reset failed attempts on successful login
            await _dbContext.SaveChangesAsync();

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim(ClaimTypes.Email, user.Email)
            };

            var identity = new ClaimsIdentity(claims, "MyCookieAuth");
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync("MyCookieAuth", principal);

            // Generate a random AuthToken
            var authToken = Guid.NewGuid().ToString();

            // Store AuthToken in session
            HttpContext.Session.SetString("AuthToken", authToken);

            // Set AuthToken as a secure cookie
            Response.Cookies.Append("AuthToken", authToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddHours(1)
            });

            // Store user email in session
            HttpContext.Session.SetString("CurrentUser", user.Email);

            var sessionExpireTime = DateTime.UtcNow.AddMinutes(30);
            HttpContext.Session.SetString("SessionExpireTime", sessionExpireTime.ToString());

            _logger.LogInformation("User {Email} logged in successfully", LModel.Email);

            return RedirectToPage("/Index");
        }

        private async Task IncrementLoginFailure(User user)
        {
            if (user == null) return;

            if (!user.IsLocked)
            {
                user.FailedLoginAttempts++;
                user.LastFailedLogin = DateTime.UtcNow;

                if (user.FailedLoginAttempts >= 3)
                {
                    user.IsLocked = true;
                }
            }

            await _dbContext.SaveChangesAsync();
        }

        private class RecaptchaResponse
        {
            public bool Success { get; set; }
            public float Score { get; set; }
            public string Action { get; set; }
            public string[] ErrorCodes { get; set; }
        }

        private async Task<User> GetCurrentUser()
        {
            var email = User.FindFirstValue(ClaimTypes.Email);
            return await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == email);
        }
    }
}
