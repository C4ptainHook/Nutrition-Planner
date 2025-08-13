using System.ComponentModel.DataAnnotations;

namespace AuthService.Authentification.Dtos;

public class ResetPasswordDto
{
    [Required, EmailAddress]
    public required string Email { get; set; }

    [Required]
    public required string OtpCode { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public required string Password { get; set; }
}
