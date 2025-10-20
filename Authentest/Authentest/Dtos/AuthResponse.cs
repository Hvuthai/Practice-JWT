using System;

namespace Authentest.Dtos;

public record AuthResponse
(
    string AccessToken,
    string RefreshToken
);
