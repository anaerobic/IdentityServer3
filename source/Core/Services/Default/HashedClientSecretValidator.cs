﻿/*
 * Copyright 2014, 2015 Dominick Baier, Brock Allen
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

using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Logging;
using IdentityServer3.Core.Models;
using System;
using System.Threading.Tasks;
using Thinktecture.IdentityModel;

namespace IdentityServer3.Core.Services.Default
{
    /// <summary>
    /// Client secret validator for hashed secrets.
    /// </summary>
    public class HashedClientSecretValidator : IClientSecretValidator
    {
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();

        /// <summary>
        /// Validates the client secret
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="credential">The client credential.</param>
        /// <returns></returns>
        public virtual Task<bool> ValidateClientSecretAsync(Client client, ClientCredential credential)
        {
            if (credential.CredentialType == Constants.ClientCredentialTypes.SharedSecret)
            {
                if (credential.ClientId.IsMissing() || credential.Credential == null || credential.Credential.ToString().IsMissing())
                {
                    throw new ArgumentNullException("Credential.ClientId or Credential.Credential");
                }

                var secretSha256 = credential.Credential.ToString().Sha256();
                var secretSha512 = credential.Credential.ToString().Sha512();

                foreach (var clientSecret in client.ClientSecrets)
                {
                    // this validator is only applicable to shared secrets
                    if (clientSecret.Type != Constants.SecretTypes.SharedSecret)
                    {
                        continue;
                    }

                    bool isValid = false;
                    byte[] clientSecretBytes;

                    // check if client secret is still valid
                    if (clientSecret.Expiration.HasExpired()) continue;

                    try
                    {
                        clientSecretBytes = Convert.FromBase64String(clientSecret.Value);
                    }
                    catch (FormatException)
                    {
                        Logger.ErrorFormat("Invalid hashing algorithm for secret for clientId: {0}", credential.ClientId);
                        return Task.FromResult(false);
                    }

                    if (clientSecretBytes.Length == 32)
                    {
                        isValid = ObfuscatingComparer.IsEqual(clientSecret.Value, secretSha256);
                    }
                    else if (clientSecretBytes.Length == 64)
                    {
                        isValid = ObfuscatingComparer.IsEqual(clientSecret.Value, secretSha512);
                    }
                    else
                    {
                        Logger.ErrorFormat("Invalid hashing algorithm for secret for clientId: {0}", credential.ClientId);
                        return Task.FromResult(false);
                    }

                    if (isValid)
                    {
                        return Task.FromResult(true);
                    }
                }
            }

            return Task.FromResult(false);
        }
    }
}