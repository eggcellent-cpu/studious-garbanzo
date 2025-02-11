using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Model
{
    public class ResetPassword
    {
        [Required(ErrorMessage = "Password is required.")]
        [StringLength(100, ErrorMessage = "Password must be at least {2} characters long.", MinimumLength = 12)]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$",
            ErrorMessage = "Password must be at least 12 characters long, including an uppercase letter, a lowercase letter, a number, and a special character.")]
        public string? Password { get; set; }

        [Required(ErrorMessage = "Please confirm your password.")]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        [DataType(DataType.Password)] 
        public string? ConfirmPassword { get; set; }

        public string? Email { get; set; }
        public string? Token { get; set; }
    }
}
