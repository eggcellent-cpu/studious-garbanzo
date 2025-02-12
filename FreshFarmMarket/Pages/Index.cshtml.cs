using FreshFarmMarket.Model;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace FreshFarmMarket.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<CustomIdentityUser> _userManager;
        private readonly MyAuthDbContext _dbContext;
        private readonly EncryptionService _encryptionService;

        public IndexModel(ILogger<IndexModel> logger, UserManager<CustomIdentityUser> userManager, MyAuthDbContext dbContext, EncryptionService encryptionService)
        {
            _logger = logger;
            _userManager = userManager;
            _dbContext = dbContext;
            _encryptionService = encryptionService;
        }

        public List<User> Users { get; set; } = new List<User>();
        public string SuccessMessage { get; set; }


        public async Task<IActionResult> OnGetAsync()
        {
            var allUsers = await _dbContext.Users.ToListAsync();

            // Decrypt sensitive fields before displaying
            Users = allUsers.Select(user => new User
            {
                UserID = user.UserID,
                FullName = user.FullName,
                Email = user.Email,
                MobileNo = _encryptionService.Decrypt(user.MobileNo),
                Gender = user.Gender,
                DeliveryAddress = _encryptionService.Decrypt(user.DeliveryAddress),
                CreditCardNo = _encryptionService.Decrypt(user.CreditCardNo),
                AboutMe = user.AboutMe,
                PhotoPath = user.PhotoPath,
                Password = user.Password // If you need to hash passwords, don't decrypt this
            }).ToList();

            if (TempData["SuccessMessage"] != null)
            {
                SuccessMessage = TempData["SuccessMessage"].ToString();
            }

            return Page();
        }
    }
}
