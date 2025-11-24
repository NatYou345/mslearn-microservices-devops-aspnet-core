using IdentityServer4.Models;
using IdentityServer4.Validation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.eShopOnContainers.Services.Identity.API.Services
{
    /// <summary>
    /// Strict redirect URI validator to mitigate GHSA-55p7-v223-x366 (Open Redirect vulnerability)
    /// </summary>
    public class StrictRedirectUriValidator : IRedirectUriValidator
    {
        private readonly HashSet<string> _allowedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "localhost",
            "127.0.0.1",
            "[::1]"
        };

        public Task<bool> IsPostLogoutRedirectUriValidAsync(string requestedUri, Client client)
        {
            return IsRedirectUriValidAsync(requestedUri, client?.PostLogoutRedirectUris);
        }

        public Task<bool> IsRedirectUriValidAsync(string requestedUri, Client client)
        {
            return IsRedirectUriValidAsync(requestedUri, client?.RedirectUris);
        }

        private Task<bool> IsRedirectUriValidAsync(string requestedUri, ICollection<string> allowedUris)
        {
            if (string.IsNullOrWhiteSpace(requestedUri))
            {
                return Task.FromResult(false);
            }

            // Parse the requested URI
            if (!Uri.TryCreate(requestedUri, UriKind.Absolute, out var uri))
            {
                return Task.FromResult(false);
            }

            // Reject any URI that is not HTTPS (except localhost for development)
            if (uri.Scheme != Uri.UriSchemeHttps && 
                uri.Scheme != Uri.UriSchemeHttp && 
                !_allowedHosts.Contains(uri.Host))
            {
                return Task.FromResult(false);
            }

            // Ensure the URI is in the allowed list
            if (allowedUris == null || !allowedUris.Any())
            {
                return Task.FromResult(false);
            }

            // Strict exact match (no wildcards, no partial matches)
            var isValid = allowedUris.Any(allowedUri => 
                string.Equals(allowedUri, requestedUri, StringComparison.OrdinalIgnoreCase));

            return Task.FromResult(isValid);
        }
    }
}
