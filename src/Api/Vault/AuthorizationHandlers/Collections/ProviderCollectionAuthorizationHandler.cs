#nullable enable
using Bit.Core;
using Bit.Core.Context;
using Bit.Core.Entities;
using Bit.Core.Enums;
using Bit.Core.Models.Data.Organizations;
using Bit.Core.Repositories;
using Bit.Core.Services;
using Microsoft.AspNetCore.Authorization;

namespace Bit.Api.Vault.AuthorizationHandlers.Collections;

/// <summary>
/// Handles authorization logic for Collection objects, including access permissions for users and groups.
/// This uses new logic implemented in the Flexible Collections initiative.
/// </summary>
public class ProviderCollectionAuthorizationHandler : AuthorizationHandler<BulkCollectionOperationRequirement, Collection>
{
    private readonly ICurrentContext _currentContext;

    public ProviderCollectionAuthorizationHandler(ICurrentContext currentContext)
    {
        _currentContext = currentContext;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
        BulkCollectionOperationRequirement requirement, Collection? resource)
    {
        // Establish pattern of authorization handler null checking passed resources
        if (resource == null)
        {
            return;
        }

        switch (requirement)
        {
            case not null when requirement == BulkCollectionOperations.Create:
            case not null when requirement == BulkCollectionOperations.Read:
            case not null when requirement == BulkCollectionOperations.ReadAccess:
            case not null when requirement == BulkCollectionOperations.Update:
            case not null when requirement == BulkCollectionOperations.ModifyAccess:
            case not null when requirement == BulkCollectionOperations.ImportCiphers:
            case not null when requirement == BulkCollectionOperations.Delete:
                if (await _currentContext.ProviderUserForOrgAsync(resource.OrganizationId))
                {
                    context.Succeed(requirement);
                }
                break;
        }
    }
}
