using Bit.Core.Utilities;
using Xunit;

namespace Bit.Core.Test.Utilities;

public class DomainNameAttributeTests
{
    [Theory]
    [InlineData("a.com")]                   // single-character domain
    [InlineData("test.com")]                // simple domain
    [InlineData("subdomain.example.net")]   // subdomain
    [InlineData("example123.co")]           // with numbers
    [InlineData("valid-domain.co.uk")]      // with hyphen
    public void IsValid_ReturnsTrueWhenValid(string domain)
    {
        var sut = new DomainNameAttribute();

        var actual = sut.IsValid(domain);

        Assert.True(actual);
    }

    [Theory]
    [InlineData(null)]                      // null
    [InlineData("")]                        // empty string
    [InlineData("invalid_domain.com")]      // underscore
    [InlineData("example@domain.com")]      // email address
    [InlineData("http://example.com")]      // protocol prefix
    [InlineData("www.example.com")]         // www prefix
    [InlineData("-startshyphen.com")]       // starts with a hyphen
    [InlineData("endswithhyphen-.com")]     // ends with a hyphen
    [InlineData("double..dots.com")]        // has two consecutive dots
    [InlineData("space inname.com")]        // has a space
    [InlineData("reallylongexamplethatiswaymorethantheallocatedlengthforadomainname.com")]        // too long
    [InlineData("example.c")]               // TLD must have at least 2 chars
    public void IsValid_ReturnsFalseWhenInvalid(string domain)
    {
        var sut = new DomainNameAttribute();

        var actual = sut.IsValid(domain);

        Assert.False(actual);
    }
}
