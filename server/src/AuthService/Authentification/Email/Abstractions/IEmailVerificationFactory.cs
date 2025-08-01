namespace AuthService.Authentification.Email.Abstractions;

public interface IEmailVerificationFactory
{
    Task<string> CreateConfirmationLink(string email);
}
