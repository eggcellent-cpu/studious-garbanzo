using Microsoft.AspNetCore.Identity;

namespace FreshFarmMarket.Model
{
    public class CustomIdentityUser : IdentityUser
    {
        public string FullName { get; set; } = string.Empty; // Full Name of the user
        public string CreditCardNo { get; set; } = string.Empty; // Encrypted Credit Card Number
        public string Gender { get; set; } = string.Empty; // Gender
        public string MobileNo { get; set; } = string.Empty; // Mobile Number
        public string DeliveryAddress { get; set; } = string.Empty; // Delivery Address
        public string AboutMe { get; set; } = string.Empty; // About Me section
        public string PhotoPath { get; set; } // JPG photo as a byte array (or a file path reference)

        public string? SessionToken { get; set; }

        public List<string> PasswordHistory { get; set; } = new List<string>(); // Store last 2 password hashes
    }
}
