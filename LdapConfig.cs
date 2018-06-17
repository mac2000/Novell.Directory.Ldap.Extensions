namespace Novell.Directory.Ldap.Extensions
{
    public class LdapConfig
	{
		public string Hostname { get; set; }
        public int Port { get; set; } = LdapConnection.DEFAULT_PORT;
		public string Domain { get; set; }
		public string BaseDn { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
	}
}