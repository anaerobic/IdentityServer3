using System;
using Microsoft.Owin.Security.DataProtection;

namespace IdentityServer3.HostvNext.Config
{
    public class MonoDataProtectionProvider : IDataProtectionProvider
    {
        private readonly string _appName;

        public MonoDataProtectionProvider()
            : this(Guid.NewGuid().ToString())
        { }

        public MonoDataProtectionProvider(string appName)
        {
            if (appName == null) { throw new ArgumentNullException("appName"); }

            _appName = appName;
        }

        public IDataProtector Create(params string[] purposes)
        {
            if (purposes == null) { throw new ArgumentNullException("purposes"); }

            return new MonoDataProtector(_appName, purposes);
        }
    }
}