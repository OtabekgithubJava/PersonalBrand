using Identity.API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using PersonalBrand.Domain.Entities.Models;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Identity.API.Services.AuthService
{
    public class AuthService : IAuthService
    {
        private IConfiguration _config;
        private readonly UserManager<UserModel> _userManager;
        public AuthService(IConfiguration config, RoleManager<IdentityRole> roleManager, UserManager<UserModel> userManager)
        {
            _config = config;
            _userManager = userManager;
        }

        public string GenerateToken(UserModel user)
        {
            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWTSettings:Secret"]!));
            SigningCredentials credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            int expirePeriod = int.Parse(_config["JWTSettings:Expire"]!);
            var roleName = _userManager.GetRolesAsync(user).Result[0];
            List<Claim> claims = new List<Claim>()
                {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
                    new Claim("UserId",user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.FirstName!),
                    new Claim(ClaimTypes.Surname, user.LastName!),
                    new Claim("Role",roleName)
                };



            JwtSecurityToken token = new JwtSecurityToken(
                issuer: _config["JWTSettings:ValidIssuer"],
                audience: _config["JWTSettings:ValidAudence"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expirePeriod),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
