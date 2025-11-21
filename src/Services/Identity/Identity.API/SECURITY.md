# Security Mitigations for IdentityServer4 Vulnerabilities

## Context
This project uses IdentityServer4 4.1.2, which is the final version before the project became end-of-life. Two moderate severity vulnerabilities exist:

1. **GHSA-55p7-v223-x366**: Open Redirect Vulnerability
2. **GHSA-ff4q-64jc-gx98**: CORS Misconfiguration Vulnerability

Since IdentityServer4 is EOL and no patches are available, this project implements runtime mitigations.

## ⚠️ WARNING FOR PRODUCTION USE
**This is a learning/demo repository.** While mitigations have been applied, IdentityServer4 should not be used in production environments. Consider migrating to:
- **Duende IdentityServer** (commercial, official successor)
- **OpenIddict** (open-source alternative)
- **Auth0, Okta, or Azure AD B2C** (managed services)

## Implemented Mitigations

### 1. Strict Redirect URI Validation (GHSA-55p7-v223-x366)
**File**: `Services/StrictRedirectUriValidator.cs`

**Vulnerability**: IdentityServer4 may incorrectly treat malicious URLs as local/trusted, allowing open redirect attacks.

**Mitigation**:
- Implements custom `IRedirectUriValidator`
- Enforces strict exact-match validation (no wildcards)
- Rejects non-HTTPS URIs (except localhost for development)
- Validates URI format before comparison
- Only allows explicitly whitelisted redirect URIs

**Code**:
```csharp
services.AddTransient<IRedirectUriValidator, StrictRedirectUriValidator>();
```

### 2. Strict CORS Policy (GHSA-ff4q-64jc-gx98)
**File**: `Services/StrictCorsPolicyService.cs`

**Vulnerability**: CORS policy misconfiguration could allow unauthorized cross-origin requests.

**Mitigation**:
- Implements custom `ICorsPolicyService`
- Maintains explicit whitelist of allowed origins
- Validates origin URI format and scheme
- Logs all CORS validation failures
- Rejects any origin not explicitly whitelisted

**Code**:
```csharp
services.AddSingleton<ICorsPolicyService, StrictCorsPolicyService>();
```

### 3. Build Warning Suppression
The `NU1902` warning is suppressed in `Identity.API.csproj` **only after** implementing the above mitigations. This indicates awareness of the vulnerabilities and documented mitigation strategy.

## Configuration Requirements

### Allowed Origins (Update for your deployment)
Edit `StrictCorsPolicyService.cs` to add your production origins:
```csharp
private readonly HashSet<string> _allowedOrigins = new HashSet<string>
{
    "https://your-production-domain.com",
    "https://your-spa.com"
};
```

### Allowed Redirect URIs
Configure in your IdentityServer4 client configuration (database or in-memory):
```csharp
RedirectUris = new List<string>
{
    "https://your-app.com/signin-oidc"
},
PostLogoutRedirectUris = new List<string>
{
    "https://your-app.com/signout-callback-oidc"
}
```

## Testing Mitigations

### Test Open Redirect Protection
```bash
# Should be rejected - malicious redirect
curl -X GET "https://identity-api/connect/authorize?redirect_uri=https://evil.com&..."

# Should be accepted - whitelisted redirect
curl -X GET "https://identity-api/connect/authorize?redirect_uri=https://your-app.com/signin-oidc&..."
```

### Test CORS Protection
```bash
# Should be rejected - non-whitelisted origin
curl -H "Origin: https://evil.com" https://identity-api/connect/token

# Should be accepted - whitelisted origin
curl -H "Origin: https://your-app.com" https://identity-api/connect/token
```

## Additional Security Recommendations

1. **Use HTTPS everywhere** - Never use HTTP in production
2. **Implement rate limiting** - Prevent brute force attacks
3. **Enable audit logging** - Track authentication attempts
4. **Regular security reviews** - Monitor for new vulnerabilities
5. **Plan migration** - Move away from IdentityServer4 when possible

## References
- [GHSA-55p7-v223-x366](https://github.com/advisories/GHSA-55p7-v223-x366)
- [GHSA-ff4q-64jc-gx98](https://github.com/advisories/GHSA-ff4q-64jc-gx98)
- [IdentityServer4 EOL Announcement](https://blog.duendesoftware.com/posts/20220111_identityserver4_eol/)
- [OpenIddict](https://github.com/openiddict/openiddict-core)
- [Duende IdentityServer](https://duendesoftware.com/products/identityserver)

## Last Updated
2025-11-21
