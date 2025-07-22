using Microsoft.EntityFrameworkCore;

namespace AuthService.Data.Extensions;

public static class MigrationExtension
{
    public static IApplicationBuilder UseMigration(this IApplicationBuilder app)
    {
        using var scope = app.ApplicationServices.CreateScope();
        using var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        dbContext.Database.Migrate();
        return app;
    }
}
