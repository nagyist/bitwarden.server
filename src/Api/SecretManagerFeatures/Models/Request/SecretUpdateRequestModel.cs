﻿using System.ComponentModel.DataAnnotations;
using Bit.Core.Entities;
using Bit.Core.Utilities;

namespace Bit.Api.SecretManagerFeatures.Models.Request;

public class SecretUpdateRequestModel
{
    [Required]
    [EncryptedString]
    public string Key { get; set; }

    [Required]
    [EncryptedString]
    public string Value { get; set; }

    [Required]
    [EncryptedString]
    public string Note { get; set; }

    public Secret ToSecret(Guid id)
    {
        return new Secret()
        {
            Id = id,
            Key = Key,
            Value = Value,
            Note = Note,
            DeletedDate = null,
        };
    }
}