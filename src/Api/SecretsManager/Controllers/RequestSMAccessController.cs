﻿using Bit.Api.SecretsManager.Models.Request;
using Bit.Core.Exceptions;
using Bit.Core.Repositories;
using Bit.Core.SecretsManager.Commands.Requests.Interfaces;
using Bit.Core.Services;
using Bit.Infrastructure.Dapper.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Bit.Api.SecretsManager.Controllers;

[Route("request-access")]
[Authorize("Web")]
public class RequestSMAccessController : Controller
{
    private readonly IRequestSMAccessCommand _requestSMAccessCommand;
    private readonly IUserService _userService;
    private readonly IOrganizationRepository _organizationRepository;
    private readonly IOrganizationUserRepository _organizationUserRepository;

    public RequestSMAccessController(
        IRequestSMAccessCommand requestSMAccessCommand, IUserService userService, IOrganizationRepository organizationRepository, IOrganizationUserRepository organizationUserRepository)
    {
        _requestSMAccessCommand = requestSMAccessCommand;
        _userService = userService;
        _organizationRepository = organizationRepository;
        _organizationUserRepository = organizationUserRepository;
    }

    [HttpPost("request-sm-access")]
    public async Task RequestSMAccessFromAdmins([FromBody] RequestSMAccessRequestModel model)
    {
        var user = await _userService.GetUserByPrincipalAsync(User);
        if (user == null)
        {
            throw new UnauthorizedAccessException();
        }

        var organization = await _organizationRepository.GetByIdAsync(model.OrganizationId);
        if (organization == null)
        {
            throw new NotFoundException();
        }

        var orgUsers = await _organizationUserRepository.GetManyDetailsByOrganizationAsync(organization.Id);
        await _requestSMAccessCommand.SendRequestAccessToSM(organization, orgUsers, user, model.EmailContent);
    }
}
