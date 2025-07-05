using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _config;

    public AdminController(UserManager<IdentityUser> userManager,
                          RoleManager<IdentityRole> roleManager,
                          IConfiguration config)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _config = config;
    }

    [Produces("application/json")]
    [HttpPost("/admin/secure")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminSecureRoute()
    {
        return Ok(new { success = true, role = "Admin", message = "Access granted" });
    }
}
