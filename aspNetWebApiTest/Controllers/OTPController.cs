//using Microsoft.AspNetCore.Authorization;
//using Microsoft.AspNetCore.Mvc;
//using System;
//using System.Numerics;
//using System.Security.Claims;

//namespace aspNetWebApiTest.Controllers
//{
//    [ApiController]
//    [Route("[controller]")]
//    public class OTPController : ControllerBase
//    {
//        [HttpPost]
//        [Authorize]
//        public IActionResult GenerateOTP([FromBody] OTPRequest request)
//        {
//            var identity = User.Identity as ClaimsIdentity;
//            if (identity != null)
//            {
//                var usernameClaim = identity.FindFirst(ClaimTypes.Name);
//                if (usernameClaim != null)
//                {
//                    string username = usernameClaim.Value;
//                    // Ýstekteki telefona OTP kodu gönder
//                    string otpCode = GenerateOTPCode();
//                    return Ok(new
//                    {
//                        otp = otpCode
//                    });
//                }
//            }

//            return BadRequest("Invalid user");
//        }

//        private string GenerateOTPCode()
//        {
//            // Basit bir þekilde rastgele bir OTP kodu üretiyoruz
//            Random random = new Random();
//            int otpNumber = random.Next(100000, 999999); // 6 haneli bir OTP kodu
//            return otpNumber.ToString();
//        }
//    }

//    public class OTPRequest
//    {
//        public string phone { get; set; }
//    }
//}
