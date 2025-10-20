using System;

namespace Authentest.Dtos;

public class RefreshRequest
{
    public string RefreshToken { get; set; } = default!;
}
