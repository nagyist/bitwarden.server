﻿using Bit.Core.Models.Api;

namespace Bit.Api.SecretsManager.Models.Response;

public class OrganizationCountsResponseModel() : ResponseModel(_objectName)
{
    private const string _objectName = "organization_counts";


    public int Projects { get; set; }

    public int Secrets { get; set; }

    public int MachineAccounts { get; set; }
}
