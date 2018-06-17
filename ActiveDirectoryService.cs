using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace Novell.Directory.Ldap.Extensions
{
    public class ActiveDirectoryService
    {
        private readonly LdapConfig _config;
        private readonly ILogger _logger;
		public ActiveDirectoryService(LdapConfig config, ILogger logger)
		{
			_config = config;
            _logger = logger;
		}
        
        public bool Validate(string username, string password)
        {
            var cn = new LdapConnection();
            try
			{
				cn.Connect(_config.Hostname, _config.Port);
				cn.Bind(username, password);
				return true;
			}
			catch (LdapException ex)
			{
                _logger.LogError(ex.ResultCode, ex, ex.Message, username);
				return false;
			}
            catch (Exception ex)
            {
                _logger.LogError(ex.HResult, ex, ex.Message, username);
                return false;
            }
            finally
            {
                if (cn != null)
                {
                    cn.Disconnect();
                }
            }
        }

        private LdapEntry GetEntry(string username)
        {
            var cn = new LdapConnection();
            try
			{
				cn.Connect(_config.Hostname, _config.Port);
				cn.Bind(_config.Username, _config.Password);
                // TODO: different searches, mail, sAMAccountName, etc
                var results = cn.Search(_config.BaseDn, LdapConnection.SCOPE_ONE, $"(sAMAccountName={username})", null, false);
				return results.next();
			}
			catch (LdapException ex)
			{
                _logger.LogError(LdapException.INVALID_CREDENTIALS, ex, ex.Message, username);
				return null;
			}
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, username);
                return null;
            }
            finally
            {
                if (cn != null)
                {
                    cn.Disconnect();
                }
            }
        }

        public ClaimsIdentity GetClaimsIdentity(string username) => GetEntry(username).GetClaimsIdentity();

        public IEnumerable<Claim> GetJwtClaims(string username) => GetEntry(username).GetJwtClaims();

        public ClaimsIdentity GetClaimsIdentity(string username, string password) => Validate(username, password)
                ? GetClaimsIdentity(username)
                : null;

        public IEnumerable<Claim> GetJwtClaims(string username, string password) => Validate(username, password)
                ? GetJwtClaims(username)
                : new List<Claim>();

    }
}