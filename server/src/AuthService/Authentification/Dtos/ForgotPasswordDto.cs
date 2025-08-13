using System.ComponentModel.DataAnnotations;

namespace AuthService.Authentification.Dtos;

public class ForgotPasswordDto
{
    [Required, EmailAddress]
    public required string Email { get; set; }
}
