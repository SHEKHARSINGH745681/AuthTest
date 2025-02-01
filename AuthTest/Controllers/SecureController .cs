using Microsoft.AspNetCore.Mvc;

[Route("api/protected")]
[ApiController]
public class ProtectedController : ControllerBase
{
    [HttpGet("secure-data")]
    [ServiceFilter(typeof(AuthorizeWithSecretKeyOrJwt))]
    public IActionResult GetSecureData()
    {
        return Ok(new { message = "Access granted!", data = "Welcome To Master Database !!" });
    }
}
