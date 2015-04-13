/*
 * Copyright 2014 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.Runtime;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Diagnostics;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using Microsoft.Framework.Logging.Console;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using Owin;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Logging;
using IdentityServer3.Core.Logging.LogProviders;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Services.Default;
using IdentityServer3.HostvNext.Config;
using Serilog;

namespace IdentityServer3.HostvNext
{
    public class Startup
    {
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddInstance(typeof(IDataProtectionProvider),
                new MonoDataProtectionProvider("idsrv3")); //services.Properties["host.AppName"] as string
        }

        //This method is invoked when ASPNET_ENV is 'Development' or is not defined
        //The allowed values are Development,Staging and Production
        public void ConfigureDevelopment(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            //Display custom error page in production when error occurs
            //During development use the ErrorPage middleware to display error information in the browser
            app.UseErrorPage(ErrorPageOptions.ShowAll);

            // Add the runtime information page that can be used by developers
            // to see what packages are used by the application
            // default path is: /runtimeinfo
            app.UseRuntimeInfoPage();

            Configure(app);
        }

        //This method is invoked when ASPNET_ENV is 'Staging'
        //The allowed values are Development,Staging and Production
        public void ConfigureStaging(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            //app.UseErrorHandler("/Home/Error");

            app.UseErrorPage(ErrorPageOptions.ShowAll);

            Configure(app);
        }

        //This method is invoked when ASPNET_ENV is 'Production'
        //The allowed values are Development,Staging and Production
        public void ConfigureProduction(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            //app.UseErrorHandler("/Home/Error");

            app.UseErrorPage(ErrorPageOptions.ShowAll);

            Configure(app);
        }

        public void Configure(IApplicationBuilder app)
        {
            LogProvider.SetCurrentLogProvider(new TraceSourceLogProvider());
			
            // setup serilog to use diagnostics trace
            //Log.Logger = new LoggerConfiguration()
            //    .WriteTo.Trace()
            //    .CreateLogger();

            // uncomment to enable HSTS headers for the host
            // see: https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security
            //app.UseHsts();

            app.UseStaticFiles();

            app.Map("/core", coreApp =>
                {
                    var factory = InMemoryFactory.Create(
                        users:   Users.Get(),
                        clients: Clients.Get(),
                        scopes:  Scopes.Get());

                    factory.CustomGrantValidator = 
                        new Registration<ICustomGrantValidator>(typeof(CustomGrantValidator));

                    factory.ConfigureClientStoreCache();
                    factory.ConfigureScopeStoreCache();
                    factory.ConfigureUserServiceCache();

                    factory.CorsPolicyService = new Registration<ICorsPolicyService>(new DefaultCorsPolicyService { AllowAll = true });

                    var idsrvOptions = new IdentityServerOptions
                    {
                        Factory = factory,
                        SigningCertificate = Cert.Load(),

                        AuthenticationOptions = new AuthenticationOptions 
                        {
                            IdentityProviders = ConfigureIdentityProviders,
                            EnablePostSignOutAutoRedirect = true
                        },

                        LoggingOptions = new LoggingOptions
                        {
                            EnableHttpLogging = true, 
                            EnableWebApiDiagnostics = true,
                            IncludeSensitiveDataInLogs = true
                        },

                        EventsOptions = new EventsOptions
                        {
                            RaiseFailureEvents = true,
                            RaiseInformationEvents = true,
                            RaiseSuccessEvents = true,
                            RaiseErrorEvents = true
                        }
                    };

                    coreApp.UseIdentityServer(idsrvOptions);
                });
        }

        public static void ConfigureIdentityProviders(IAppBuilder app, string signInAsType)
        {
        }
    }
}