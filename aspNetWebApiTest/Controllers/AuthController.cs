using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Data.OleDb;
using System.IdentityModel.Tokens.Jwt;
using System.Numerics;
using System.Security.Claims;
using System.Text;

namespace aspNetWebApiTest.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class OAuthController : ControllerBase
    {
        private const string CLIENT_ID = "your_client_id";
        private const string GRANT_TYPE = "your_grant_type";
        private const string CLIENT_SECRET = "your_secret_key_here_your_secret_key_here_your_secret_key_here_your_secret_key_here";
        public static readonly SymmetricSecurityKey SigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(CLIENT_SECRET));



        [HttpPost("token")]
        public IActionResult GetToken([FromBody] TokenRequest request)
        {
            if (request.client_id == CLIENT_ID && request.client_secret == CLIENT_SECRET && request.grant_type == GRANT_TYPE)
            {
                var token = CreateToken("username");
                var expiresAt = DateTime.UtcNow.AddMinutes(30);
                return Ok(new
                {
                    token_type = "Bearer",
                    access_token = token,
                    expires_at = expiresAt,
                    test = "ok"
                });
            }
            else
            {
                return BadRequest("Invalid client credentials");
            }
        }

        private string CreateToken(string username)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                        {
                            new Claim(ClaimTypes.Name, username)
                        }),
                Expires = now.AddMinutes(30),
                SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }

    public class TokenRequest
    {
        public string client_id { get; set; }
        public string client_secret { get; set; }
        public string grant_type { get; set; }
    }

    [ApiController]
    [Route("[controller]")]
    public class OTPController : ControllerBase
    {
        [HttpPost]
        [Authorize]
        public IActionResult GenerateOTP([FromBody] OTPRequest request)
        {
            var identity = User.Identity as ClaimsIdentity;
            if (identity != null)
            {
                var usernameClaim = identity.FindFirst(ClaimTypes.Name);
                if (usernameClaim != null)
                {
                    string username = usernameClaim.Value;

                    string otpCode = GenerateOTPCode();
                    //telefona OTP kodu gönder

                    //eðer phone var ise insert_update
                    string connectionString = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=C:\\Users\\Ugur\\source\\repos\\aspNetWebApiTest\\aspNetWebApiTest\\DbTest.accdb;";
                    using (var connection = new OleDbConnection(connectionString))
                    {
                        connection.Open();
                        //string sql = "INSERT INTO otpControl (phone, otp) VALUES (@Phone, @OtpCode)";
                        //using (var command = new OleDbCommand(sql, connection))
                        //{
                        //    command.Parameters.AddWithValue("@Phone", request.phone);
                        //    command.Parameters.AddWithValue("@OtpCode", otpCode);
                        //    command.ExecuteNonQuery();
                        //}

                        string selectSql = "SELECT COUNT(*) FROM otpControl WHERE phone = @Phone";
                        using (var selectCommand = new OleDbCommand(selectSql, connection))
                        {
                            selectCommand.Parameters.AddWithValue("@Phone", request.phone);
                            int existingRecordsCount = (int)selectCommand.ExecuteScalar();

                            if (existingRecordsCount > 0)
                            {
                                string updateSql = "UPDATE otpControl SET otp = @OtpCode WHERE phone = @Phone";
                                using (var updateCommand = new OleDbCommand(updateSql, connection))
                                {
                                    updateCommand.Parameters.AddWithValue("@Phone", request.phone);
                                    updateCommand.Parameters.AddWithValue("@OtpCode", otpCode);
                                    updateCommand.ExecuteNonQuery();
                                }
                            }
                            else
                            {
                                string insertSql = "INSERT INTO otpControl (phone, otp) VALUES (@Phone, @OtpCode)";
                                using (var insertCommand = new OleDbCommand(insertSql, connection))
                                {
                                    insertCommand.Parameters.AddWithValue("@Phone", request.phone);
                                    insertCommand.Parameters.AddWithValue("@OtpCode", otpCode);
                                    insertCommand.ExecuteNonQuery();
                                }
                            }
                        }
                    }


                    //return Ok(new
                    //{
                    //    otp = otpCode
                    //});
                    return Ok();
                }
            }
            return BadRequest("Invalid user");
        }

        private string GenerateOTPCode()
        {
            Random random = new Random();
            int otpNumber = random.Next(100000, 999999);
            return otpNumber.ToString();
        }
    }

    public class OTPRequest
    {
        public string phone { get; set; }
    }


    [ApiController]
    [Route("[controller]")]
    public class OTPValidateController : ControllerBase
    {
        private const string CLIENT_SECRET = "your_secret_key_here_your_secret_key_here_your_secret_key_here_your_secret_key_here";
        public static readonly SymmetricSecurityKey SigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(CLIENT_SECRET));

        [HttpPost]
        [Authorize]
        public IActionResult validateOTP([FromBody] OTPValidate request)
        {
            var identity = User.Identity as ClaimsIdentity;
            if (identity != null)
            {
                var usernameClaim = identity.FindFirst(ClaimTypes.Name);
                if (usernameClaim != null)
                {
                    string username = usernameClaim.Value;

                    string connectionString = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=C:\\Users\\Ugur\\source\\repos\\aspNetWebApiTest\\aspNetWebApiTest\\DbTest.accdb;";
                    using (var connection = new OleDbConnection(connectionString))
                    {
                        connection.Open();

                        string sql = "SELECT otp FROM otpControl WHERE phone = @Phone";
                        using (var command = new OleDbCommand(sql, connection))
                        {
                            command.Parameters.AddWithValue("@Phone", request.phone);
                            var otpCodeControl = command.ExecuteScalar();

                            if (otpCodeControl.ToString() == request.otp)
                            {
                                connection.Close();
                                var token = CreateToken(request.phone);
                                var expiresAt = DateTime.UtcNow.AddMinutes(90);
                                string sql1 = "SELECT COUNT(*) FROM customer WHERE phone = @Phone";
                                using (var command1 = new OleDbCommand(sql1, connection))
                                {
                                    command1.Parameters.AddWithValue("@Phone", request.phone);
                                    int existingRecordsCount = (int)command1.ExecuteScalar();
                                    if (existingRecordsCount == 0)
                                    {
                                        return Ok(new
                                        {
                                            token_type = "Bearer",
                                            customer_token = token,
                                            expires_at = expiresAt,
                                            register = true
                                        });
                                    }
                                    else {
                                        return Ok(new
                                        {
                                            token_type = "Bearer",
                                            customer_token = token,
                                            expires_at = expiresAt,
                                            register = false
                                        });
                                    }
                                }
                            }
                            else
                            {
                                connection.Close();
                                return NotFound("OTP not found for the given phone number");
                            }
                        }
                    }
                }
            }
            return BadRequest("Invalid user");
        }

        private string CreateToken(string phone)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                        {
                            new Claim(ClaimTypes.MobilePhone, phone)
                        }),
                Expires = now.AddMinutes(90),
                SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }

    public class OTPValidate
    {
        public string phone { get; set; }
        public string otp { get; set; }
    }


    [ApiController]
    [Route("[controller]")]
    public class RegisterController : ControllerBase
    {
        private const string CLIENT_SECRET = "your_secret_key_here_your_secret_key_here_your_secret_key_here_your_secret_key_here";
        public static readonly SymmetricSecurityKey SigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(CLIENT_SECRET));

        [HttpPost]
        [Authorize]
        public IActionResult Register([FromBody] Register request)
        {
            var identity = User.Identity as ClaimsIdentity;
            if (identity != null)
            {
                var usernameClaim = identity.FindFirst(ClaimTypes.MobilePhone);
                if (usernameClaim != null)
                {
                    string connectionString = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=C:\\Users\\Ugur\\source\\repos\\aspNetWebApiTest\\aspNetWebApiTest\\DbTest.accdb;";
                    string insertSql = "INSERT INTO customer (user, phone, mail, birthDate) VALUES (@user, @phone, @mail, @birthDate)";
                    using (var connection = new OleDbConnection(connectionString))
                    {
                        connection.Open();
                        string sql = "SELECT otp FROM otpControl WHERE phone = @Phone";
                        using (var command = new OleDbCommand(sql, connection))
                        {
                            command.Parameters.AddWithValue("@Phone", request.phone);
                            var otpCodeControl = command.ExecuteScalar();

                            if (otpCodeControl.ToString() == request.otp.ToString())
                            {
                                using (var insertCommand = new OleDbCommand(insertSql, connection))
                                {
                                    insertCommand.Parameters.AddWithValue("@user", request.name);
                                    insertCommand.Parameters.AddWithValue("@phone", request.phone);
                                    insertCommand.Parameters.AddWithValue("@mail", request.mail);
                                    insertCommand.Parameters.AddWithValue("@birthDate", request.birthDate);
                                    insertCommand.ExecuteNonQuery();
                                    return Ok();
                                }                      
                            }
                            else
                            {
                                return NotFound("OTP not found for the given phone number");
                            }
                        }
                    }
                }           
            }
            return BadRequest("Invalid user");
        }
    }


    public class Register
    {
        public string name { get; set; }
        public int phone { get; set; }
        public string mail { get; set; }
        public DateOnly birthDate { get; set; }
        public int otp { get; set; }

    }
}
