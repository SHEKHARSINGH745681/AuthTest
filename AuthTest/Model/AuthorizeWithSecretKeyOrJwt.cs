using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;

public class AuthorizeWithSecretKeyOrJwt : Attribute, IAuthorizationFilter
{
    private readonly string _secretKey;
    private readonly string _jwtSecret;

    public AuthorizeWithSecretKeyOrJwt(string secretKey, string jwtSecret)
    {
        _secretKey = secretKey;
        _jwtSecret = jwtSecret;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var httpContext = context.HttpContext;
        var authorizationHeader = httpContext.Request.Headers["Authorization"].FirstOrDefault();
        var secretKeyHeader = httpContext.Request.Headers["X-Secret-Key"].FirstOrDefault();

        bool isJwtValid = false;
        bool isSecretKeyValid = secretKeyHeader == _secretKey;

        // Check if the request contains a Bearer token
        if (!string.IsNullOrEmpty(authorizationHeader) && authorizationHeader.StartsWith("Bearer "))
        {
            var token = authorizationHeader.Substring("Bearer ".Length).Trim();
            isJwtValid = ValidateJwtToken(token);
        }

        // Allow access if either the JWT token or the secret key is valid
        if (!isJwtValid && !isSecretKeyValid)
        {
            context.Result = new UnauthorizedResult();
        }
    }

    private bool ValidateJwtToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSecret);

            // Validate the JWT token
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            return validatedToken != null;
        }
        catch
        {
            return false;
        }
    }
}
