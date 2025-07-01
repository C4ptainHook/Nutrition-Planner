using AuthService.Registration;
using Riok.Mapperly.Abstractions;

namespace AuthService.Mappings;

[Mapper]
public partial class RegistrationMapper
{
    public partial RegistrationCommand ToCommand(RegistrationRequest result);

    public partial RegistrationResponse ToResponse(RegistrationResult response);
}
