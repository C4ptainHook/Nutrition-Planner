using AuthService.Authentification.Dtos;
using AuthService.Authentification.Email.Abstractions;
using AuthService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Authentification;

[ApiController]
[Route("api/v1/auth")]
public class AuthenticationController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailComposer _emailComposer;
    private readonly IEmailSender _emailSender;
    private readonly IEmailVerificationFactory _emailVerificationFactory;

    public AuthenticationController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IEmailComposer emailComposer,
        IEmailSender emailSender,
        IEmailVerificationFactory emailVerificationFactory
    )
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _emailComposer = emailComposer;
        _emailSender = emailSender;
        _emailVerificationFactory = emailVerificationFactory;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);
        await _userManager.AddToRoleAsync(user, "guest");
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors.Select(e => e.Description));
        }
        var confirmationLink = await _emailVerificationFactory.CreateConfirmationLink(user.Email);
        var confirmationEmail = _emailComposer.CreateConfirmationEmail(
            user.Email,
            confirmationLink
        );
        await _emailSender.VerifyEmailAsync(confirmationEmail);
        return CreatedAtAction(nameof(Register), new { email = user.Email });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user is null || user.EmailConfirmed == false)
        {
            return Unauthorized("Email not confirmed or user does not exist.");
        }
        var result = await _signInManager.PasswordSignInAsync(
            model.Email,
            model.Password,
            isPersistent: false,
            lockoutOnFailure: false
        );
        if (!result.Succeeded)
        {
            return Unauthorized("Invalid login attempt.");
        }
        return Ok();
    }

    [HttpGet("confirm-email", Name = "ConfirmEmail")]
    public async Task<IActionResult> ConfirmEmail(
        [FromQuery] string email,
        [FromQuery] string token
    )
    {
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
        {
            return BadRequest("Email and token are required.");
        }
        var user = await _userManager.FindByEmailAsync(email);
        if (user is null)
        {
            return NotFound("User not found.");
        }
        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (!result.Succeeded)
        {
            return BadRequest("Email confirmation failed.");
        }
        return Ok("Email confirmed successfully.");
    }
}
