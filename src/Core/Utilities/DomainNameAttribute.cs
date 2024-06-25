﻿using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace Bit.Core.Utilities;

public partial class DomainNameAttribute : ValidationAttribute
{
    public DomainNameAttribute()
        : base("The {0} field is not a valid domain name format. Expected format: mydomain.com. Subdomains require separate entries to be verified.")
    { }

    // Domain labels (sections) are only allowed to be 63 chars in length max
    // 1st and last chars cannot be hyphens per RFC 3696 (https://www.rfc-editor.org/rfc/rfc3696#section-2)
    // We do not want any prefixes per industry standards.

    // Must support top-level domains and any number of subdomains.
    //   /                               # start regex
    //   ^                               # start of string
    //   (?!(http(s)?:\/\/|www\.))       # negative lookahead to check if input doesn't match "http://", "https://" or "www."
    //   [a-zA-Z0-9]                     # first character must be a letter or a number
    //   [a-zA-Z0-9-]{0,61}              # domain name can have 0 to 61 characters that are letters, numbers, or hyphens
    //   [a-zA-Z0-9]                     # domain name must end with a letter or a number
    //   (?:                             # start of non-capturing group (subdomain sections are optional)
    //     \.                               # subdomain must have a period
    //     [a-zA-Z0-9]                      # first character of subdomain must be a letter or a number
    //     [a-zA-Z0-9-]{0,61}               # subdomain can have 0 to 61 characters that are letters, numbers, or hyphens
    //     [a-zA-Z0-9]                      # subdomain must end with a letter or a number
    //   )*                              # end of non-capturing group (subdomain sections are optional)
    //   \.                              # domain name must have a period
    //   [a-zA-Z]{2,}                    # domain name must have at least two letters (the domain extension)
    //   $/                              # end of string
    [GeneratedRegex(@"^(?!(http(s)?:\/\/|www\.))[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*\.[a-zA-Z]{2,}$")]
    private static partial Regex DomainValidationRegex();

    public override bool IsValid(object value)
    {
        var domain = value?.ToString();
        return domain != null && DomainValidationRegex().IsMatch(domain);
    }
}
