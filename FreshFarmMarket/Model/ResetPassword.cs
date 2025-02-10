using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Model
{
    public class ResetPassword
    {
        [Required]
        [DataType(DataType.Password)]
        public string? Password { get; set; }

        [Required]
        public string? ConfirmPassword { get; set; }

        public string? Email { get; set; }
        public string? Token { get; set; }
    }
}
