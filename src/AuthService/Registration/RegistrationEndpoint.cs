using AuthService.Mappings;
using Carter;
using Wolverine;

namespace AuthService.Registration;

public record RegistrationRequest(string Nickname, string Email, string Password);

public record RegistrationResponse(string UserId);

public class RegistrationEndpoint : ICarterModule
{
    private readonly RegistrationMapper _mapper = new();

    public void AddRoutes(IEndpointRouteBuilder app)
    {
        app.MapPost(
                "api/v1/register",
                async (IMessageBus bus, RegistrationRequest request) =>
                {
                    var command = _mapper.ToCommand(request);
                    var result = await bus.InvokeAsync<RegistrationResult>(command);
                    var response = _mapper.ToResponse(result);
                    return Results.Created($"/api/v1/users/{response.UserId}", response);
                }
            )
            .Produces<RegistrationResponse>(StatusCodes.Status201Created)
            .Produces(StatusCodes.Status400BadRequest)
            .AllowAnonymous();
    }
}
