namespace FreshFarmMarket.ViewModels
{
    public class RecaptchaResponse
    {
        public bool Success { get; set; }
        public float Score { get; set; }
        public string Action { get; set; }
        public string[] ErrorCodes { get; set; }
    }

}
