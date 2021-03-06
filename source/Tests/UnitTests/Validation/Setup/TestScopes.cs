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

using System.Collections.Generic;
using IdentityServer3.Core.Models;

namespace IdentityServer3.Tests.Validation
{
    class TestScopes
    {
        public static IEnumerable<Scope> Get()
        {
            return new Scope[]
            {
                StandardScopes.OpenId,
                StandardScopes.Profile,
                StandardScopes.OfflineAccess,

                new Scope
                {
                    Name = "resource",
                    Description = "resource scope",
                    Type = ScopeType.Resource
                },
                new Scope
                {
                    Name = "resource2",
                    Description = "resource scope",
                    Type = ScopeType.Resource
                },
             };
        }
    }
}