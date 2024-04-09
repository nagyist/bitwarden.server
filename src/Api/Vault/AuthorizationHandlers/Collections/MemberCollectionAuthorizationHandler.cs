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
public class MemberCollectionAuthorizationHandler : AuthorizationHandler<BulkCollectionOperationRequirement, Collection>
{
    private readonly ICurrentContext _currentContext;
    private readonly ICollectionRepository _collectionRepository;
    private readonly IApplicationCacheService _applicationCacheService;
    private readonly IFeatureService _featureService;
    private HashSet<Guid>? _managedCollectionsIds;

    public MemberCollectionAuthorizationHandler(
        ICurrentContext currentContext,
        ICollectionRepository collectionRepository,
        IApplicationCacheService applicationCacheService,
        IFeatureService featureService)
    {
        _currentContext = currentContext;
        _collectionRepository = collectionRepository;
        _applicationCacheService = applicationCacheService;
        _featureService = featureService;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
        BulkCollectionOperationRequirement requirement, Collection? resource)
    {
        // Establish pattern of authorization handler null checking passed resources
        if (resource == null)
        {
            return;
        }

        var org = _currentContext.GetOrganization(resource.OrganizationId);
        if (org == null)
        {
            // User is not a member of the org and cannot be authorized by this handler
            return;
        }

        switch (requirement)
        {
            case not null when requirement == BulkCollectionOperations.Create:
                await CanCreateAsync(context, requirement, resource);
                break;

            case not null when requirement == BulkCollectionOperations.Read:
            case not null when requirement == BulkCollectionOperations.ReadAccess:
                await CanReadAsync(context, requirement, resource);
                break;

            case not null when requirement == BulkCollectionOperations.ReadWithAccess:
                await CanReadWithAccessAsync(context, requirement, resource);
                break;

            case not null when requirement == BulkCollectionOperations.Update:
            case not null when requirement == BulkCollectionOperations.ModifyAccess:
            case not null when requirement == BulkCollectionOperations.ImportCiphers:
                await CanUpdateCollectionAsync(context, requirement, resource);
                break;

            case not null when requirement == BulkCollectionOperations.Delete:
                await CanDeleteAsync(context, requirement, resource);
                break;
        }
    }

    private async Task CanCreateAsync(AuthorizationHandlerContext context, IAuthorizationRequirement requirement,
        Collection resource)
    {
        var org = _currentContext.GetOrganization(resource.OrganizationId);

        // Owners, Admins, and users with CreateNewCollections permission can always create collections
        if (org is
        { Type: OrganizationUserType.Owner or OrganizationUserType.Admin } or
        { Permissions.CreateNewCollections: true })
        {
            context.Succeed(requirement);
            return;
        }

        // If the limit collection management setting is disabled, allow any user to create collections
        if (await GetOrganizationAbilityAsync(resource) is { LimitCollectionCreationDeletion: false })
        {
            context.Succeed(requirement);
        }
    }

    private async Task CanReadAsync(AuthorizationHandlerContext context, IAuthorizationRequirement requirement,
        Collection resource)
    {
        var org = _currentContext.GetOrganization(resource.OrganizationId);

        // Owners, Admins, and users with EditAnyCollection or DeleteAnyCollection permission can always read a collection
        if (org is
        { Type: OrganizationUserType.Owner or OrganizationUserType.Admin } or
        { Permissions.EditAnyCollection: true } or
        { Permissions.DeleteAnyCollection: true })
        {
            context.Succeed(requirement);
            return;
        }

        // The acting user is a member of the target organization,
        // ensure they have access for the collection being read
        if (org is not null)
        {
            var canManageCollections = await CanManageCollectionAsync(resource);
            if (canManageCollections)
            {
                context.Succeed(requirement);
            }
        }
    }

    private async Task CanReadWithAccessAsync(AuthorizationHandlerContext context, IAuthorizationRequirement requirement,
        Collection resource)
    {
        var org = _currentContext.GetOrganization(resource.OrganizationId);

        // Owners, Admins, and users with EditAnyCollection, DeleteAnyCollection or ManageUsers permission can always read a collection
        if (org is
        { Type: OrganizationUserType.Owner or OrganizationUserType.Admin } or
        { Permissions.EditAnyCollection: true } or
        { Permissions.DeleteAnyCollection: true } or
        { Permissions.ManageUsers: true })
        {
            context.Succeed(requirement);
            return;
        }

        // The acting user is a member of the target organization,
        // ensure they have access with manage permission for the collection being read
        if (org is not null)
        {
            var canManageCollections = await CanManageCollectionAsync(resource);
            if (canManageCollections)
            {
                context.Succeed(requirement);
            }
        }
    }

    /// <summary>
    /// Ensures the acting user is allowed to update the target collections or manage access permissions for them.
    /// </summary>
    private async Task CanUpdateCollectionAsync(AuthorizationHandlerContext context,
        IAuthorizationRequirement requirement, Collection resource)
    {
        var org = _currentContext.GetOrganization(resource.OrganizationId);

        // Users with EditAnyCollection permission can always update a collection
        if (org is
            { Permissions.EditAnyCollection: true })
        {
            context.Succeed(requirement);
            return;
        }

        // If V1 is enabled, Owners and Admins can update any collection only if permitted by collection management settings
        var organizationAbility = await GetOrganizationAbilityAsync(resource);
        if ((organizationAbility is { AllowAdminAccessToAllCollectionItems: true } || !_featureService.IsEnabled(FeatureFlagKeys.FlexibleCollectionsV1)) &&
            org is { Type: OrganizationUserType.Owner or OrganizationUserType.Admin })
        {
            context.Succeed(requirement);
            return;
        }

        // The acting user is a member of the target organization,
        // ensure they have manage permission for the collection being managed
        if (org is not null)
        {
            var canManageCollections = await CanManageCollectionAsync(resource);
            if (canManageCollections)
            {
                context.Succeed(requirement);
            }
        }
    }

    private async Task CanDeleteAsync(AuthorizationHandlerContext context, IAuthorizationRequirement requirement,
        Collection resource)
    {
        var org = _currentContext.GetOrganization(resource.OrganizationId);

        // Owners, Admins, and users with DeleteAnyCollection permission can always delete collections
        if (org is
        { Type: OrganizationUserType.Owner or OrganizationUserType.Admin } or
        { Permissions.DeleteAnyCollection: true })
        {
            context.Succeed(requirement);
            return;
        }

        // Check for non-null org here: the user must be apart of the organization for this setting to take affect
        // The limit collection management setting is disabled,
        // ensure acting user has manage permissions for all collections being deleted
        if (await GetOrganizationAbilityAsync(resource) is { LimitCollectionCreationDeletion: false })
        {
            var canManageCollections = await CanManageCollectionAsync(resource);
            if (canManageCollections)
            {
                context.Succeed(requirement);
            }
        }
    }

    private async Task<bool> CanManageCollectionAsync(Collection targetCollection)
    {
        if (_managedCollectionsIds == null)
        {
            var allUserCollections = await _collectionRepository
                .GetManyByUserIdAsync(_currentContext.UserId!.Value, useFlexibleCollections: true);
            _managedCollectionsIds = allUserCollections
                .Where(c => c.Manage)
                .Select(c => c.Id)
                .ToHashSet();
        }

        return _managedCollectionsIds.Contains(targetCollection.Id);
    }

    private async Task<OrganizationAbility?> GetOrganizationAbilityAsync(Collection resource)
    {
        return await _applicationCacheService.GetOrganizationAbilityAsync(resource.OrganizationId);
    }
}
