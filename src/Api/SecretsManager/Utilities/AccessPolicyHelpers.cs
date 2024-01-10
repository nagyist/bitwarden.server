﻿using Bit.Core.Exceptions;
using Bit.Core.SecretsManager.Entities;

namespace Bit.Api.SecretsManager.Utilities;

public class AccessPolicyHelpers
{
    public static void CheckForDistinctAccessPolicies(IReadOnlyCollection<BaseAccessPolicy> accessPolicies)
    {
        var distinctAccessPolicies = accessPolicies.DistinctBy(baseAccessPolicy =>
        {
            return baseAccessPolicy switch
            {
                UserProjectAccessPolicy ap => new Tuple<Guid?, Guid?>(ap.OrganizationUserId, ap.GrantedProjectId),
                GroupProjectAccessPolicy ap => new Tuple<Guid?, Guid?>(ap.GroupId, ap.GrantedProjectId),
                ServiceAccountProjectAccessPolicy ap => new Tuple<Guid?, Guid?>(ap.ServiceAccountId,
                    ap.GrantedProjectId),
                UserServiceAccountAccessPolicy ap => new Tuple<Guid?, Guid?>(ap.OrganizationUserId,
                    ap.GrantedServiceAccountId),
                GroupServiceAccountAccessPolicy ap => new Tuple<Guid?, Guid?>(ap.GroupId, ap.GrantedServiceAccountId),
                _ => throw new ArgumentException("Unsupported access policy type provided.", nameof(baseAccessPolicy)),
            };
        }).ToList();

        if (accessPolicies.Count != distinctAccessPolicies.Count)
        {
            throw new BadRequestException("Resources must be unique");
        }
    }

    public static void CheckAccessPoliciesHasReadPermission(IReadOnlyCollection<BaseAccessPolicy> accessPolicies)
    {
        var accessPoliciesPermission = accessPolicies.All(Policy => Policy.Read); //Has to be read, write can be true or false.
        if (!accessPoliciesPermission)
        {
            throw new BadRequestException("Resources must be Read = true");
        }
    }
}
