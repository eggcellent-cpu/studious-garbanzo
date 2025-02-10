using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Model
{
    public class ForgotPassword
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }

        [Required]
        public string? ClientUrl { get; set; }
    }
}
