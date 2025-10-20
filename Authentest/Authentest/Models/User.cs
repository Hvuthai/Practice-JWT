using System;
using System.ComponentModel.DataAnnotations;

namespace Authentest.Models;

public class User
{
    public int Id { get; set; }


    [Required]
    [MaxLength(256)]
    public string Email { get; set; }


    [Required]
    public string PasswordHash { get; set; }


    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;


    public ICollection<RefreshToken> RefreshTokens { get; set; }
}
