using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.eShopOnContainers.Services.Identity.API.Models;
using Microsoft.eShopOnContainers.Services.Identity.API.Models.AccountViewModels;
using Microsoft.eShopOnContainers.Services.Identity.API.Services;
using System.Threading.Tasks;

namespace Microsoft.eShopOnContainers.Services.Identity.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JwtTokenService _jwtTokenService;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            JwtTokenService jwtTokenService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtTokenService = jwtTokenService;
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);

            if (result.Succeeded)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                var token = await _jwtTokenService.GenerateJwtToken(user);
                
                return Ok(new { token, user = new { user.Email, user.UserName } });
            }

            return Unauthorized(new { message = "Invalid login attempt" });
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                CardNumber = model.User?.CardNumber,
                CardHolderName = model.User?.CardHolderName,
                CardType = model.User?.CardType ?? 0,
                City = model.User?.City,
                Country = model.User?.Country,
                Expiration = model.User?.Expiration,
                LastName = model.User?.LastName,
                Name = model.User?.Name,
                PhoneNumber = model.User?.PhoneNumber,
                SecurityNumber = model.User?.SecurityNumber,
                State = model.User?.State,
                Street = model.User?.Street,
                ZipCode = model.User?.ZipCode
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                var token = await _jwtTokenService.GenerateJwtToken(user);
                
                return Ok(new { token, user = new { user.Email, user.UserName } });
            }

            return BadRequest(result.Errors);
        }

        [HttpGet("user")]
        [Authorize]
        public async Task<IActionResult> GetUser()
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);
            if (user == null)
                return NotFound();

            return Ok(new
            {
                user.Email,
                user.UserName,
                user.Name,
                user.LastName,
                user.PhoneNumber
            });
        }
    }
}
