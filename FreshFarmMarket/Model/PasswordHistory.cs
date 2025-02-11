namespace FreshFarmMarket.Model
{
    public class PasswordHistory
    {
        public int Id { get; set; }
        public string UserId { get; set; } // Foreign key to the user
        public string HashedPassword { get; set; } // Hashed password
        public DateTime CreatedAt { get; set; } // Timestamp of when the password was set
    }
}
