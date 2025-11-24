using IdentityServer4.Services;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.eShopOnContainers.Services.Identity.API.Services
{
    /// <summary>
    /// Strict CORS policy service to mitigate GHSA-ff4q-64jc-gx98 (CORS misconfiguration vulnerability)
    /// </summary>
    public class StrictCorsPolicyService : ICorsPolicyService
    {
        private readonly ILogger<StrictCorsPolicyService> _logger;
        private readonly HashSet<string> _allowedOrigins;

        public StrictCorsPolicyService(ILogger<StrictCorsPolicyService> logger)
        {
            _logger = logger;
            
            // Define strict allowed origins (update these based on your deployment)
            _allowedOrigins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "http://localhost",
                "http://localhost:5100",
                "http://localhost:5101",
                "http://localhost:5102",
                "http://localhost:5103",
                "http://localhost:5104",
                "http://localhost:5105",
                "http://localhost:5106",
                "http://localhost:5107",
                "http://localhost:5108",
                "https://localhost",
                "https://localhost:5100",
                "https://localhost:5101",
                "https://localhost:5102",
                "https://localhost:5103",
                "https://localhost:5104",
                "https://localhost:5105",
                "https://localhost:5106",
                "https://localhost:5107",
                "https://localhost:5108"
            };
        }

        public Task<bool> IsOriginAllowedAsync(string origin)
        {
            if (string.IsNullOrWhiteSpace(origin))
            {
                _logger.LogWarning("CORS check failed: empty origin");
                return Task.FromResult(false);
            }

            // Parse the origin to ensure it's a valid URI
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
            {
                _logger.LogWarning("CORS check failed: invalid URI format for origin: {Origin}", origin);
                return Task.FromResult(false);
            }

            // Check if the origin's scheme is allowed (only HTTP/HTTPS)
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            {
                _logger.LogWarning("CORS check failed: invalid scheme {Scheme} for origin: {Origin}", 
                    uri.Scheme, origin);
                return Task.FromResult(false);
            }

            // Normalize origin (remove trailing slash, convert to lowercase)
            var normalizedOrigin = $"{uri.Scheme}://{uri.Authority}".ToLowerInvariant();

            // Check against whitelist
            var isAllowed = _allowedOrigins.Contains(normalizedOrigin);

            if (!isAllowed)
            {
                _logger.LogWarning("CORS check failed: origin not in whitelist: {Origin}", origin);
            }

            return Task.FromResult(isAllowed);
        }
    }
}
