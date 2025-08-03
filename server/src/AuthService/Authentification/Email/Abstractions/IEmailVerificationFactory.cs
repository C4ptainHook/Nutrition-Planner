namespace AuthService.Authentification.Email.Abstractions;

public interface IEmailLinkFactory
{
    Task<string> CreateConfirmationLink(string email);
}
