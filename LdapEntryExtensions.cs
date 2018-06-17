using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using IdentityModel;

namespace Novell.Directory.Ldap.Extensions
{
    public static class LdapEntryExtensions
    {
        private static IEnumerable<Claim> GetClaims(this LdapEntry entry, string email, string name, string role) {
            var claims = new List<Claim>();
            claims.Add(new Claim(email, entry.GetMail()));
            claims.Add(new Claim(name, entry.GetName()));
            claims.AddRange(entry.GetGroups().Select(group => new Claim(role, group)));
            return claims;
        }

        public static string GetStringValue(this LdapEntry entry, string key)
        {
            var attr = entry.getAttribute(key);
            return attr == null || string.IsNullOrEmpty(attr.StringValue)
                ? ""
                : attr.StringValue;
        }

        public static IEnumerable<string> GetStringValues(this LdapEntry entry, string key)
        {
            var items = new List<string>(); 

            var attr = entry.getAttribute(key);
            if (attr == null)
            {
                return items;
            }

            var values = attr.StringValues;
            while (values.MoveNext())
            {
                items.Add(values.Current.ToString());
            }

            return items;
        }

        public static string GetName(this LdapEntry entry) => entry.GetStringValue("name");

        public static string GetMail(this LdapEntry entry) => entry.GetStringValue("mail");

        public static string GetSubjectId(this LdapEntry entry) => entry.GetStringValue("sAMAccountName");

        public static IEnumerable<string> GetGroups(this LdapEntry entry) => entry.GetStringValues("MemberOf").Select(group => group.Split(',').FirstOrDefault()?.Replace("CN=", ""));

        public static IEnumerable<Claim> GetJwtClaims(this LdapEntry entry) => entry.GetClaims(JwtClaimTypes.Email, JwtClaimTypes.Name, JwtClaimTypes.Role);

        public static IEnumerable<Claim> GetIdentityClaims(this LdapEntry entry) => entry.GetClaims(ClaimTypes.Email, ClaimTypes.Name, ClaimTypes.Role);

        public static ClaimsIdentity GetClaimsIdentity(this LdapEntry entry) => new ClaimsIdentity(new GenericIdentity(entry.GetSubjectId()), entry.GetIdentityClaims());
    }
}
