using System;
using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Model
{
    public class User
    {
        public Guid UserID { get; set; }

        [Required, StringLength(100)]
        public string FullName { get; set; }

        [Required, EmailAddress]
        public string Email { get; set; }

        [StringLength(256)] 
        public string MobileNo { get; set; }

        public string Gender { get; set; }

        [StringLength(256)]
        public string DeliveryAddress { get; set; }


        [MinLength(16), MaxLength(256)]
        public string CreditCardNo { get; set; }

        public string AboutMe { get; set; }

        public string PhotoPath { get; set; }

        public int FailedLoginAttempts { get; set; } = 0;
        public bool IsLocked { get; set; } = false;
        public DateTime? LastFailedLogin { get; set; }
        public bool LockoutEnabled { get; set; }
        public DateTime? PasswordLastChanged { get; set; } 

        public string Password { get; set; }
    }
}
