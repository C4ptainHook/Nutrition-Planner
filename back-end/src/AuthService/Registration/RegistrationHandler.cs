using AuthService.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthService.Registration;

public record RegistrationCommand(string Nickname, string Email, string Password);

public record RegistrationResult(string UserId);

public class RegistrationHandler(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager
)
{
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;

    public async Task<RegistrationResult> Handle(RegistrationCommand command)
    {
        var isRegistered = await _userManager.FindByEmailAsync(command.Email) is not null;
        if (isRegistered)
        {
            throw new Exception("User already registered");
        }

        var newUser = new ApplicationUser { UserName = command.Email, Email = command.Email };
        var result = await _userManager.CreateAsync(newUser, command.Password);
        if (!result.Succeeded)
        {
            throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
        }
        await _signInManager.SignInAsync(newUser, isPersistent: false);
        return new RegistrationResult(newUser.Id);
    }
}
