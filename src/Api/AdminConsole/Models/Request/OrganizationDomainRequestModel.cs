using System.ComponentModel.DataAnnotations;
using Bit.Core.Utilities;

namespace Bit.Api.AdminConsole.Models.Request;

public class OrganizationDomainRequestModel
{
    [Required]
    [DomainName]
    public string DomainName { get; set; }
}
