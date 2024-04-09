using System.Security.Claims;
using Bit.Api.Vault.AuthorizationHandlers.Collections;
using Bit.Core;
using Bit.Core.Context;
using Bit.Core.Entities;
using Bit.Core.Enums;
using Bit.Core.Models.Data;
using Bit.Core.Models.Data.Organizations;
using Bit.Core.Repositories;
using Bit.Core.Services;
using Bit.Core.Test.Vault.AutoFixture;
using Bit.Test.Common.AutoFixture;
using Bit.Test.Common.AutoFixture.Attributes;
using Microsoft.AspNetCore.Authorization;
using NSubstitute;
using Xunit;

namespace Bit.Api.Test.Vault.AuthorizationHandlers;

[SutProviderCustomize]
public class MemberCollectionAuthorizationHandlerTests
{
    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.Admin)]
    [BitAutoData(OrganizationUserType.Owner)]
    public async Task CanCreateAsync_WhenAdminOrOwner_Success(
        OrganizationUserType userType,
        Guid userId, SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        organization.Type = userType;
        organization.Permissions = new Permissions();

        ArrangeOrganizationAbility(sutProvider, organization, true);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.Create },
            new ClaimsPrincipal(),
            collection);

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

        await sutProvider.Sut.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanCreateAsync_WhenUser_WithLimitCollectionCreationDeletionFalse_Success(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = OrganizationUserType.User;

        ArrangeOrganizationAbility(sutProvider, organization, false);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.Create },
            new ClaimsPrincipal(),
            collection);

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

        await sutProvider.Sut.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.User)]
    [BitAutoData(OrganizationUserType.Custom)]
    public async Task CanCreateAsync_WhenMissingPermissions_NoSuccess(
        OrganizationUserType userType,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = userType;
        organization.Permissions = new Permissions
        {
            EditAnyCollection = false,
            DeleteAnyCollection = false,
            ManageGroups = false,
            ManageUsers = false
        };

        ArrangeOrganizationAbility(sutProvider, organization, true);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.Create },
            new ClaimsPrincipal(),
            collection);

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);
        sutProvider.GetDependency<ICurrentContext>().ProviderUserForOrgAsync(Arg.Any<Guid>()).Returns(false);

        await sutProvider.Sut.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanCreateAsync_WhenMissingOrgAccess_NoSuccess(
        Guid userId,
        CurrentContextOrganization organization,
        List<Collection> collections,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider)
    {
        collections.ForEach(c => c.OrganizationId = organization.Id);
        ArrangeOrganizationAbility(sutProvider, organization, true);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.Create },
            new ClaimsPrincipal(),
            collections
        );

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(Arg.Any<Guid>()).Returns((CurrentContextOrganization)null);
        sutProvider.GetDependency<ICurrentContext>().ProviderUserForOrgAsync(Arg.Any<Guid>()).Returns(false);

        await sutProvider.Sut.HandleAsync(context);
        Assert.False(context.HasSucceeded);
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.Admin)]
    [BitAutoData(OrganizationUserType.Owner)]
    public async Task CanReadAsync_WhenAdminOrOwner_Success(
        OrganizationUserType userType,
        Guid userId, SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        organization.Type = userType;
        organization.Permissions = new Permissions();

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Read, BulkCollectionOperations.ReadAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

            var context = new AuthorizationHandlerContext(
                new[] { BulkCollectionOperations.Read },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.True(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, CollectionCustomization]
    [BitAutoData(true, false)]
    [BitAutoData(false, true)]
    public async Task CanReadAsync_WhenCustomUserWithRequiredPermissions_Success(
        bool editAnyCollection, bool deleteAnyCollection,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = OrganizationUserType.Custom;
        organization.Permissions = new Permissions
        {
            EditAnyCollection = editAnyCollection,
            DeleteAnyCollection = deleteAnyCollection
        };

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Read, BulkCollectionOperations.ReadAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

            var context = new AuthorizationHandlerContext(
                new[] { BulkCollectionOperations.Read },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.True(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanReadAsync_WhenUserCanManageCollections_Success(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        CollectionDetails collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();
        collection.Manage = true;

        organization.Type = OrganizationUserType.User;
        organization.Permissions = new Permissions();

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Read, BulkCollectionOperations.ReadAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);
            sutProvider.GetDependency<ICollectionRepository>()
                .GetManyByUserIdAsync(actingUserId, Arg.Any<bool>())
                .Returns(new [] { collection });

            var context = new AuthorizationHandlerContext(
                new[] { BulkCollectionOperations.Read },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.True(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanReadAsync_WhenUserIsNotAssignedToCollections_NoSuccess(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        CollectionDetails collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = OrganizationUserType.User;
        organization.Permissions = new Permissions();

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Read, BulkCollectionOperations.ReadAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

            var context = new AuthorizationHandlerContext(
                new[] { BulkCollectionOperations.Read },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.False(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.User)]
    [BitAutoData(OrganizationUserType.Custom)]
    public async Task CanReadAsync_WhenMissingPermissions_NoSuccess(
        OrganizationUserType userType,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = userType;
        organization.Permissions = new Permissions
        {
            EditAnyCollection = false,
            DeleteAnyCollection = false,
            ManageGroups = false,
            ManageUsers = false
        };

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Read, BulkCollectionOperations.ReadAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

            var context = new AuthorizationHandlerContext(
                new[] { BulkCollectionOperations.Read },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.False(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanReadAsync_WhenMissingOrgAccess_NoSuccess(
        Guid userId,
        Collection collection,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider)
    {
        var operationsToTest = new[]
        {
            BulkCollectionOperations.Read, BulkCollectionOperations.ReadAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(Arg.Any<Guid>()).Returns((CurrentContextOrganization)null);

            var context = new AuthorizationHandlerContext(
                new[] { op },
                new ClaimsPrincipal(),
                collection
            );

            await sutProvider.Sut.HandleAsync(context);

            Assert.False(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.Admin)]
    [BitAutoData(OrganizationUserType.Owner)]
    public async Task CanReadWithAccessAsync_WhenAdminOrOwner_Success(
        OrganizationUserType userType,
        Guid userId, SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        organization.Type = userType;
        organization.Permissions = new Permissions();

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.ReadWithAccess },
            new ClaimsPrincipal(),
            collection);

        await sutProvider.Sut.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Theory, CollectionCustomization]
    [BitAutoData(true, false, false)]
    [BitAutoData(false, true, false)]
    [BitAutoData(false, false, true)]

    public async Task CanReadWithAccessAsync_WhenCustomUserWithRequiredPermissions_Success(
        bool editAnyCollection, bool deleteAnyCollection, bool manageUsers,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = OrganizationUserType.Custom;
        organization.Permissions = new Permissions
        {
            EditAnyCollection = editAnyCollection,
            DeleteAnyCollection = deleteAnyCollection,
            ManageUsers = manageUsers
        };

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.ReadWithAccess },
            new ClaimsPrincipal(),
            collection);

        await sutProvider.Sut.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanReadWithAccessAsync_WhenUserCanManageCollections_Success(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        CollectionDetails collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        collection.Manage = true;
        organization.Type = OrganizationUserType.User;
        organization.Permissions = new Permissions();

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);
        sutProvider.GetDependency<ICollectionRepository>()
            .GetManyByUserIdAsync(actingUserId, Arg.Any<bool>())
            .Returns(new [] {collection});

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.ReadWithAccess },
            new ClaimsPrincipal(),
            collection);

        await sutProvider.Sut.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanReadWithAccessAsync_WhenUserCanNotManageCollections_Success(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        CollectionDetails collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        collection.Manage = false;

        organization.Type = OrganizationUserType.User;
        organization.Permissions = new Permissions();

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);
        sutProvider.GetDependency<ICollectionRepository>()
            .GetManyByUserIdAsync(actingUserId, Arg.Any<bool>())
            .Returns(new [] { collection });

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.ReadWithAccess },
            new ClaimsPrincipal(),
            collection);

        await sutProvider.Sut.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.User)]
    [BitAutoData(OrganizationUserType.Custom)]
    public async Task CanReadWithAccessAsync_WhenMissingPermissions_NoSuccess(
        OrganizationUserType userType,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = userType;
        organization.Permissions = new Permissions
        {
            EditAnyCollection = false,
            DeleteAnyCollection = false,
            ManageGroups = false,
            ManageUsers = false
        };

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.ReadWithAccess },
            new ClaimsPrincipal(),
            collection);

        await sutProvider.Sut.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanReadWithAccessAsync_WhenMissingOrgAccess_NoSuccess(
        Guid userId,
        Collection collection,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider)
    {
        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(Arg.Any<Guid>()).Returns((CurrentContextOrganization)null);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.ReadWithAccess },
            new ClaimsPrincipal(),
            collection
        );

        await sutProvider.Sut.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.Admin)]
    [BitAutoData(OrganizationUserType.Owner)]
    public async Task CanUpdateCollection_WhenAdminOrOwner_WithoutV1Enabled_Success(
        OrganizationUserType userType,
        Guid userId, SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        organization.Type = userType;
        organization.Permissions = new Permissions();

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Update, BulkCollectionOperations.ModifyAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

            var context = new AuthorizationHandlerContext(
                new[] { op },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.True(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.Admin)]
    [BitAutoData(OrganizationUserType.Owner)]
    public async Task CanUpdateCollection_WhenAdminOrOwner_WithV1Enabled_PermittedByCollectionManagementSettings_Success(
        OrganizationUserType userType,
        Guid userId, SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection, CurrentContextOrganization organization,
        OrganizationAbility organizationAbility)
    {
        organization.Type = userType;
        organization.Permissions = new Permissions();
        organizationAbility.Id = organization.Id;
        organizationAbility.AllowAdminAccessToAllCollectionItems = true;

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Update, BulkCollectionOperations.ModifyAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);
            sutProvider.GetDependency<IApplicationCacheService>().GetOrganizationAbilityAsync(organization.Id)
                .Returns(organizationAbility);
            sutProvider.GetDependency<IFeatureService>().IsEnabled(FeatureFlagKeys.FlexibleCollectionsV1).Returns(true);

            var context = new AuthorizationHandlerContext(
                new[] { op },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.True(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.Admin)]
    [BitAutoData(OrganizationUserType.Owner)]
    public async Task CanUpdateCollection_WhenAdminOrOwner_WithV1Enabled_NotPermittedByCollectionManagementSettings_Failure(
        OrganizationUserType userType,
        Guid userId, SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection, CurrentContextOrganization organization,
        OrganizationAbility organizationAbility)
    {
        organization.Type = userType;
        organization.Permissions = new Permissions();
        organizationAbility.Id = organization.Id;
        organizationAbility.AllowAdminAccessToAllCollectionItems = false;

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Update, BulkCollectionOperations.ModifyAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);
            sutProvider.GetDependency<IApplicationCacheService>().GetOrganizationAbilityAsync(organization.Id)
                .Returns(organizationAbility);
            sutProvider.GetDependency<IFeatureService>().IsEnabled(FeatureFlagKeys.FlexibleCollectionsV1).Returns(true);

            var context = new AuthorizationHandlerContext(
                new[] { op },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.False(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanUpdateCollection_WithEditAnyCollectionPermission_Success(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = OrganizationUserType.Custom;
        organization.Permissions = new Permissions
        {
            EditAnyCollection = true
        };

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Update, BulkCollectionOperations.ModifyAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

            var context = new AuthorizationHandlerContext(
                new[] { op },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.True(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanUpdateCollection_WithManageCollectionPermission_Success(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        CollectionDetails collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = OrganizationUserType.User;
        organization.Permissions = new Permissions();
        collection.Manage = true;

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Update, BulkCollectionOperations.ModifyAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);
            sutProvider.GetDependency<ICollectionRepository>()
                .GetManyByUserIdAsync(actingUserId, Arg.Any<bool>())
                .Returns(new [] { collection});

            var context = new AuthorizationHandlerContext(
                new[] { op },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.True(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.User)]
    [BitAutoData(OrganizationUserType.Custom)]
    public async Task CanUpdateCollection_WhenMissingPermissions_NoSuccess(
        OrganizationUserType userType,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        CollectionDetails collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = userType;
        organization.Permissions = new Permissions
        {
            EditAnyCollection = false,
            DeleteAnyCollection = false,
            ManageGroups = false,
            ManageUsers = false
        };

        collection.Manage = false;

        var operationsToTest = new[]
        {
            BulkCollectionOperations.Update, BulkCollectionOperations.ModifyAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

            var context = new AuthorizationHandlerContext(
                new[] { op },
                new ClaimsPrincipal(),
                collection);

            await sutProvider.Sut.HandleAsync(context);

            Assert.False(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanUpdateCollection_WhenMissingOrgAccess_NoSuccess(
        Guid userId,
        Collection collection,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider)
    {
        var operationsToTest = new[]
        {
            BulkCollectionOperations.Update, BulkCollectionOperations.ModifyAccess
        };

        foreach (var op in operationsToTest)
        {
            sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
            sutProvider.GetDependency<ICurrentContext>().GetOrganization(Arg.Any<Guid>()).Returns((CurrentContextOrganization)null);

            var context = new AuthorizationHandlerContext(
                new[] { op },
                new ClaimsPrincipal(),
                collection
            );

            await sutProvider.Sut.HandleAsync(context);

            Assert.False(context.HasSucceeded);

            // Recreate the SUT to reset the mocks/dependencies between tests
            sutProvider.Recreate();
        }
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.Admin)]
    [BitAutoData(OrganizationUserType.Owner)]
    public async Task CanDeleteAsync_WhenAdminOrOwner_Success(
        OrganizationUserType userType,
        Guid userId, SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        organization.Type = userType;
        organization.Permissions = new Permissions();

        ArrangeOrganizationAbility(sutProvider, organization, true);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.Delete },
            new ClaimsPrincipal(),
            collection);

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

        await sutProvider.Sut.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanDeleteAsync_WithDeleteAnyCollectionPermission_Success(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = OrganizationUserType.Custom;
        organization.Permissions = new Permissions
        {
            DeleteAnyCollection = true
        };

        ArrangeOrganizationAbility(sutProvider, organization, true);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.Delete },
            new ClaimsPrincipal(),
            collection);

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);

        await sutProvider.Sut.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanDeleteAsync_WithManageCollectionPermission_Success(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        CollectionDetails collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = OrganizationUserType.User;
        organization.Permissions = new Permissions();

        ArrangeOrganizationAbility(sutProvider, organization, false);

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);
        sutProvider.GetDependency<ICollectionRepository>()
            .GetManyByUserIdAsync(actingUserId, Arg.Any<bool>())
            .Returns(new[] {collection});

        collection.Manage = true;

        var context = new AuthorizationHandlerContext(
                new[] { BulkCollectionOperations.Delete },
                new ClaimsPrincipal(),
                collection);

        await sutProvider.Sut.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Theory, CollectionCustomization]
    [BitAutoData(OrganizationUserType.User)]
    [BitAutoData(OrganizationUserType.Custom)]
    public async Task CanDeleteAsync_WhenMissingPermissions_NoSuccess(
        OrganizationUserType userType,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        Collection collection,
        CurrentContextOrganization organization)
    {
        var actingUserId = Guid.NewGuid();

        organization.Type = userType;
        organization.Permissions = new Permissions
        {
            EditAnyCollection = false,
            DeleteAnyCollection = false,
            ManageGroups = false,
            ManageUsers = false
        };

        ArrangeOrganizationAbility(sutProvider, organization, true);

        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.Delete },
            new ClaimsPrincipal(),
            collection);

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);
        sutProvider.GetDependency<ICurrentContext>().ProviderUserForOrgAsync(Arg.Any<Guid>()).Returns(false);

        await sutProvider.Sut.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CanDeleteAsync_WhenMissingOrgAccess_NoSuccess(
        Guid userId,
        Collection collection,
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider)
    {
        var context = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.Delete },
            new ClaimsPrincipal(),
            collection
        );

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(userId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(Arg.Any<Guid>()).Returns((CurrentContextOrganization)null);
        sutProvider.GetDependency<ICurrentContext>().ProviderUserForOrgAsync(Arg.Any<Guid>()).Returns(false);

        await sutProvider.Sut.HandleAsync(context);
        Assert.False(context.HasSucceeded);
    }

    [Theory, BitAutoData, CollectionCustomization]
    public async Task CachesCollectionsWithCanManagePermissions(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        CollectionDetails collection1, CollectionDetails collection2,
        CurrentContextOrganization organization, Guid actingUserId)
    {
        organization.Type = OrganizationUserType.User;
        organization.Permissions = new Permissions();

        sutProvider.GetDependency<ICurrentContext>().UserId.Returns(actingUserId);
        sutProvider.GetDependency<ICurrentContext>().GetOrganization(organization.Id).Returns(organization);
        sutProvider.GetDependency<ICollectionRepository>()
            .GetManyByUserIdAsync(actingUserId, Arg.Any<bool>())
            .Returns(new List<CollectionDetails>() { collection1, collection2 });

        var context1 = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.Update },
            new ClaimsPrincipal(),
            collection1);

        await sutProvider.Sut.HandleAsync(context1);

        var context2 = new AuthorizationHandlerContext(
            new[] { BulkCollectionOperations.Update },
            new ClaimsPrincipal(),
            collection2);

        await sutProvider.Sut.HandleAsync(context2);

        // Expect: only calls the database once
        await sutProvider.GetDependency<ICollectionRepository>().Received(1).GetManyByUserIdAsync(Arg.Any<Guid>(), Arg.Any<bool>());
    }

    private static void ArrangeOrganizationAbility(
        SutProvider<MemberCollectionAuthorizationHandler> sutProvider,
        CurrentContextOrganization organization, bool limitCollectionCreationDeletion)
    {
        var organizationAbility = new OrganizationAbility();
        organizationAbility.Id = organization.Id;
        organizationAbility.FlexibleCollections = true;
        organizationAbility.LimitCollectionCreationDeletion = limitCollectionCreationDeletion;

        sutProvider.GetDependency<IApplicationCacheService>().GetOrganizationAbilityAsync(organizationAbility.Id)
            .Returns(organizationAbility);
    }
}
