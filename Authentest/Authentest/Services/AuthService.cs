using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Authentest.Dtos;
using Authentest.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
namespace Authentest.Services;

public class AuthService : IAuthService
{
    private readonly AppDbContext _db;
    private readonly IConfiguration _config;
    public AuthService(AppDbContext db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    public async Task RegisterAsync(RegisterRequest request)
    {
        if (await _db.Users.AnyAsync(u => u.Email == request.Email))
            throw new Exception("Email already in use");

        var user = new User
        {
            Email = request.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();
    }

    public async Task<AuthResult> LoginAsync(LoginRequest request)
    {
        var user = await _db.Users.Include(u => u.RefreshTokens)
            .FirstOrDefaultAsync(u => u.Email == request.Email);

        if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            throw new Exception("Invalid credentials");

        var accessToken = GenerateAccessToken(user);
        var refreshToken = GenerateRefreshToken();

        var rt = new RefreshToken
        {
            Token = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddDays(_config.GetSection("Jwt").GetValue<int>("RefreshTokenExpirationDays")),
            UserId = user.Id
        };

        _db.RefreshTokens.Add(rt);
        await _db.SaveChangesAsync();

        return new AuthResult(accessToken, refreshToken);
    }

    public async Task<AuthResult> RefreshTokenAsync(string refreshToken)
    {
        var rt = await _db.RefreshTokens.Include(r => r.User)
            .FirstOrDefaultAsync(r => r.Token == refreshToken);

        if (rt == null || rt.IsRevoked || rt.ExpiresAt <= DateTime.UtcNow)
            throw new Exception("Invalid refresh token");

        // rotate: revoke old token and issue new
        rt.IsRevoked = true;

        var newAccess = GenerateAccessToken(rt.User);
        var newRefresh = GenerateRefreshToken();

        var newRt = new RefreshToken
        {
            Token = newRefresh,
            ExpiresAt = DateTime.UtcNow.AddDays(_config.GetSection("Jwt").GetValue<int>("RefreshTokenExpirationDays")),
            UserId = rt.UserId
        };

        _db.RefreshTokens.Add(newRt);
        await _db.SaveChangesAsync();

        return new AuthResult(newAccess, newRefresh);
    }

    public async Task LogoutAsync(string refreshToken)
    {
        var rt = await _db.RefreshTokens.FirstOrDefaultAsync(r => r.Token == refreshToken);
        if (rt == null) return;
        rt.IsRevoked = true;
        await _db.SaveChangesAsync();
    }


    private string GenerateAccessToken(User user)
    {
        var jwtSection = _config.GetSection("Jwt");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection.GetValue<string>("Key")));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);


        var claims = new[]
        {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };


        var token = new JwtSecurityToken(
        issuer: jwtSection.GetValue<string>("Issuer"),
        audience: jwtSection.GetValue<string>("Audience"),
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(jwtSection.GetValue<int>("AccessTokenExpirationMinutes")),
        signingCredentials: creds
        );


        return new JwtSecurityTokenHandler().WriteToken(token);
    }


    private string GenerateRefreshToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }
}
