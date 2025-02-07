using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace FreshFarmMarket.ViewModels
{
    public class Register
    {
        [Required(ErrorMessage = "Full Name is required")]
        [StringLength(100, ErrorMessage = "Full Name cannot exceed 100 characters")]
        public string FullName { get; set; } = string.Empty;


        [Required(ErrorMessage = "Credit Card Number is required")]
        [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit card number must be exactly 16 digits.")]
        [DataType(DataType.CreditCard)]
        public string CreditCardNo { get; set; } = string.Empty;


        [Required(ErrorMessage = "Gender is required")]
        public string Gender { get; set; } = string.Empty;


        [Required(ErrorMessage = "Mobile Number is required")]
        [RegularExpression(@"^[0-9]{8,15}$", ErrorMessage = "Mobile Number must be between 8-15 digits")]
        public string MobileNo { get; set; } = string.Empty;


        [Required(ErrorMessage = "Delivery Address is required")]
        [StringLength(250, ErrorMessage = "Delivery Address cannot exceed 250 characters")]
        public string DeliveryAddress { get; set; } = string.Empty;


        [Required(ErrorMessage = "Email Address is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address format")]
        public string Email { get; set; } = string.Empty;


        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [MinLength(12, ErrorMessage = "Password must be at least 12 characters long")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$",
            ErrorMessage = "Password must have at least one lowercase letter, one uppercase letter, one number, and one special character")]
        public string Password { get; set; } = string.Empty;


        [Required(ErrorMessage = "Confirm Password is required")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Password and Confirm Password do not match")]
        public string ConfirmPassword { get; set; } = string.Empty;


        [Required(ErrorMessage = "Photo is required")]
        [DataType(DataType.Upload)]
        public required IFormFile Photo { get; set; }


        [Required(ErrorMessage = "About Me is required")]
        [StringLength(500, ErrorMessage = "About Me cannot exceed 500 characters")]
        public string AboutMe { get; set; } = string.Empty;
    }
}
