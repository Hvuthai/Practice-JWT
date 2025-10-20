using System;
using Authentest.Dtos;
using Authentest.Models;

namespace Authentest.Services;

public interface IAuthService
{
        public Task RegisterAsync(RegisterRequest request);
        public Task<AuthResult> LoginAsync(LoginRequest request);
        public Task<AuthResult> RefreshTokenAsync(string refreshToken);
        public Task LogoutAsync(string refreshToken);
}

public record AuthResult(string AccessToken, string RefreshToken);
