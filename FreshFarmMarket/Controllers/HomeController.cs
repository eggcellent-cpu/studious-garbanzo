using FreshFarmMarket.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace FreshFarmMarket.Controllers
{
    public class HomeController : Controller
    {
        private readonly SignInManager<CustomIdentityUser> _signInManager;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public HomeController(SignInManager<CustomIdentityUser> signInManager, IHttpContextAccessor httpContextAccessor)
        {
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
        }

        [HttpPost]
        public async Task<IActionResult> ClearSession()
        {
            // Clear session
            _httpContextAccessor.HttpContext.Session.Clear();

            // Clear authentication cookies
            await _signInManager.SignOutAsync();

            // Clear TempData
            TempData.Clear();

            return Ok();
        }
    }
}
