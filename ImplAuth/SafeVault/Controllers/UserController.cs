using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _config;

    public UserController(UserManager<IdentityUser> userManager,
                          RoleManager<IdentityRole> roleManager,
                          IConfiguration config)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _config = config;
    }


    [Produces("application/json")]
    [HttpPost("/user/secure")]
    [Authorize(Roles = "User")]
    public IActionResult Index()
    {
        return Ok(new { message = "Welcome secure route user.", StatusCode = 200, role = "User" });
    }
}
