
using PersonalBrand.Domain.Entities.Models;

namespace Identity.API.Services.AuthService
{
    public interface IAuthService
    {
        public string GenerateToken(UserModel user);
    }
}
