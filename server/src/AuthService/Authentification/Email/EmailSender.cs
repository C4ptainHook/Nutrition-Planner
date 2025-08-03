using AuthService.Authentification.Email.Abstractions;
using MailKit.Net.Smtp;
using MimeKit;

namespace AuthService.Authentification.Email;

public sealed class EmailSender(IConfiguration configuration) : IEmailSender
{
    public async Task SendEmailAsync(MimeMessage message)
    {
        using var client = new SmtpClient();
        client.Connect(
            configuration["EmailSettings:SmtpServer"]!,
            int.Parse(configuration["EmailSettings:SmtpPort"]!)
        );
        await client.SendAsync(message);
        client.Disconnect(true);
    }
}
