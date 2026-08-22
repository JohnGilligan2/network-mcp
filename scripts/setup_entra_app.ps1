<#
  setup_entra_app.ps1 — provision the Entra app + security group for the
  Network Device MCP server, via Microsoft Graph PowerShell (Mg* cmdlets).

  Automates Parts A & B of docs/ENTRA_SETUP_CHECKLIST.md:
    A1 create app (single tenant)   A2 App ID URI = the /mcp URL
    A3 expose scope access_as_user  A4 client secret (printed ONCE)
    A5 both redirect URIs           A6 requestedAccessTokenVersion = 2
    B1 security group + members     B2 assignment required
    B3 assign group to the app (falls back to per-user if no P1/P2)

  RUN AS an Entra admin (Application Administrator + Groups Administrator, or
  Global Admin). This CHANGES auth on shared infra — review before running.
  The client secret it prints goes into Claude's connector Advanced settings,
  NOT the server env and NOT into chat.

  RUN THIS FIRST:
      .\setup_entra_app.ps1 -ResolveOnly
  It resolves every teammate against the directory and prints what it found,
  creating nothing. Confirm the table before the real run.

  MEMBERS: the approved engineers .

  Understand what this group grants before adding to it. It is not "can read a
  dashboard" — it is read-only CLI access to every managed router, switch and
  firewall, using the shared device credential, driven from a chat window. The
  target allowlist is currently OPEN, so group membership is the primary access
  control in the system. Offboarding someone means removing them here.

  Prereqs:
    Install-Module Microsoft.Graph.Applications, Microsoft.Graph.Groups,
                   Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement `
                   -Scope CurrentUser
#>

param(
    # Tenant to register in. Accepts the domain or the tenant GUID. REQUIRED in
    # our multi-domain setup so the app lands in the directory the users
    # actually sign in with, not whatever Connect-MgGraph defaults to.
    [string]$TenantId = 'examplecorp.com',

    # Resolve members and print the table, then exit. Creates nothing.
    [switch]$ResolveOnly,

    # Skip the confirmation prompt (for unattended re-runs once verified).
    [switch]$Force,

    # Abort instead of continuing when a member cannot be resolved.
    [switch]$StrictMembers
)

$ErrorActionPreference = 'Stop'

# ---- CONFIG ---------------------------------------------------------------
$AppName   = 'Network Device MCP'
$McpUrl    = 'https://network-mcp.example.com/mcp'   # == App ID URI == ENTRA_IDENTIFIER_URI
$ScopeName = 'access_as_user'
$GroupName = 'Network-MCP-Users'
$GroupNick = 'network-mcp-users'
$RedirectUris = @(
    'https://claude.ai/api/mcp/auth_callback',
    'https://claude.com/api/mcp/auth_callback'
)

# Members of the access group. Each entry carries CANDIDATE sign-in addresses
# (tried in order) plus a Surname used as the last-resort directory search.
# Our UPNs and mail addresses do not always share a domain, so both are tried.
#
# DELIBERATELY STARTS WITH ONE MEMBER, unlike the other MCP servers. Membership
# here is not "can read a dashboard" — it is a login shell on every router,
# switch and firewall we manage, with the shared admin credential, from a chat
# window. That is a different grant from Proxmox monitoring or IT Glue lookups,
# and it should be a per-person decision rather than a copied list.
#
# Uncomment the engineers who should genuinely have it, run with -ResolveOnly
# first, and check the resolved table before the real run.
$MemberSpecs = @(
    @{ Label = 'John Gilligan'
       Candidates = @('approver@example.com', 'approver@example.com')
       Surname = 'Gilligan' }
    @{ Label = 'Alice Example'
       Candidates = @('approver@example.com', 'approver@example.com')
       Surname = 'Example' }
    @{ Label = 'Bob Example'
       Candidates = @('approver@example.com', 'approver@example.com')
       Surname = 'Example' }
    @{ Label = 'Carol Example'
       Candidates = @('approver@example.com', 'approver@example.com')
       Surname = 'Example' }
    @{ Label = 'Dan Example'
       Candidates = @('approver@example.com', 'approver@example.com')
       Surname = 'Example' }
)

$DefaultAccessRoleId = '00000000-0000-0000-0000-000000000000'  # "default access" app role
# ---------------------------------------------------------------------------

$connectArgs = @{ Scopes = @(
    'Application.ReadWrite.All',
    'Group.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All',
    'User.Read.All',
    'Organization.Read.All',
    # Needed for C1/C2 below — the 23:59 access-token lifetime policy.
    'Policy.ReadWrite.ApplicationConfiguration'
) }
if ($TenantId) { $connectArgs['TenantId'] = $TenantId }
Connect-MgGraph @connectArgs | Out-Null

$ctxTenant = (Get-MgContext).TenantId
$org = Get-MgOrganization | Select-Object -First 1
$verified = @($org.VerifiedDomains | ForEach-Object { $_.Name })
Write-Host "Connected to tenant $ctxTenant ($($org.DisplayName))" -ForegroundColor Cyan
Write-Host "Verified domains: $($verified -join ', ')" -ForegroundColor DarkGray

# Guard: the connected tenant must be the one asked for, by GUID or by domain.
if ($TenantId -and $TenantId -ne $ctxTenant -and $verified -notcontains $TenantId) {
    throw ("Connected tenant '$ctxTenant' does not match -TenantId '$TenantId' " +
           "(not its id and not one of its verified domains). Aborting so the " +
           "app does not land in the wrong directory.")
}

# ---- Resolve members ------------------------------------------------------
function Resolve-Member {
    param([hashtable]$Spec)

    foreach ($cand in $Spec.Candidates) {
        # 1) exact UPN
        try {
            $u = Get-MgUser -UserId $cand -Property 'id,displayName,userPrincipalName,mail' -ErrorAction Stop
            if ($u) { return [pscustomobject]@{ User = $u; How = 'UPN' } }
        } catch { }
        # 2) exact mail (mail often differs from the UPN domain here)
        try {
            $m = @(Get-MgUser -Filter "mail eq '$cand'" -Property 'id,displayName,userPrincipalName,mail' -ErrorAction Stop)
            if ($m.Count -eq 1) { return [pscustomobject]@{ User = $m[0]; How = 'mail' } }
        } catch { }
    }
    # 3) last resort: surname search — this is what catches a misspelled UPN
    if ($Spec.Surname) {
        try {
            $s = @(Get-MgUser -Filter "startswith(surname,'$($Spec.Surname)')" `
                              -Property 'id,displayName,userPrincipalName,mail' -All -ErrorAction Stop)
            if ($s.Count -eq 1) { return [pscustomobject]@{ User = $s[0]; How = "surname '$($Spec.Surname)'" } }
            if ($s.Count -gt 1) {
                return [pscustomobject]@{ User = $null; How = 'AMBIGUOUS'
                                          Note = ($s | ForEach-Object { $_.UserPrincipalName }) -join ' | ' }
            }
        } catch { }
    }
    return [pscustomobject]@{ User = $null; How = 'NOT FOUND'; Note = '' }
}

Write-Host "`nResolving group members against the directory..." -ForegroundColor Cyan
$resolved = @()
foreach ($spec in $MemberSpecs) {
    $r = Resolve-Member -Spec $spec
    $resolved += [pscustomobject]@{
        Asked   = $spec.Label
        Found   = if ($r.User) { $r.User.DisplayName } else { '—' }
        UPN     = if ($r.User) { $r.User.UserPrincipalName } else { '—' }
        Matched = $r.How
        Note    = $r.Note
        Id      = if ($r.User) { $r.User.Id } else { $null }
    }
}
$resolved | Format-Table Asked, Found, UPN, Matched, Note -AutoSize

$unresolved = @($resolved | Where-Object { -not $_.Id })
if ($unresolved.Count -gt 0) {
    Write-Host ("UNRESOLVED: " + (($unresolved | ForEach-Object { $_.Asked }) -join ', ')) -ForegroundColor Yellow
    Write-Host "Fix the Candidates/Surname in `$MemberSpecs, or add them by hand in Entra afterwards." -ForegroundColor Yellow
    if ($StrictMembers) { throw "Aborting: -StrictMembers set and $($unresolved.Count) member(s) unresolved." }
}

if ($ResolveOnly) {
    Write-Host "`n-ResolveOnly: nothing was created. Re-run without the switch when the table looks right." -ForegroundColor Cyan
    return
}

if (-not $Force) {
    Write-Host "`nAbout to create Entra app '$AppName', App ID URI $McpUrl," -ForegroundColor Yellow
    Write-Host "and security group '$GroupName' with $(@($resolved | Where-Object Id).Count) member(s)." -ForegroundColor Yellow
    $ans = Read-Host "Type YES to proceed"
    if ($ans -ne 'YES') { Write-Host 'Aborted.' -ForegroundColor Red; return }
}

# Guard against duplicates
if (Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue) {
    throw "An app named '$AppName' already exists. Delete it or rename before re-running."
}

# --- A1: create the app (single tenant) + A5 redirect URIs -----------------
$app = New-MgApplication -DisplayName $AppName -SignInAudience 'AzureADMyOrg' `
    -Web @{ RedirectUris = $RedirectUris }
Write-Host "A1  Created app. Client ID = $($app.AppId)" -ForegroundColor Green

# --- A2 App ID URI + A3 scope + A6 token v2 (one Update) ------------------
$scope = @{
    id                      = [guid]::NewGuid().ToString()
    value                   = $ScopeName
    type                    = 'User'          # "Admins and users" can consent
    isEnabled               = $true
    adminConsentDisplayName = 'Access Network Device MCP as the signed-in user'
    adminConsentDescription = 'Allows the connector to read configuration and show-command output from managed network devices on behalf of the signed-in user. Read-only.'
    userConsentDisplayName  = 'Access Network Device MCP'
    userConsentDescription  = 'Allow the connector to read network device configuration on your behalf.'
}
Update-MgApplication -ApplicationId $app.Id `
    -IdentifierUris @($McpUrl) `
    -Api @{ RequestedAccessTokenVersion = 2; Oauth2PermissionScopes = @($scope) }
Write-Host "A2/A3/A6  Set App ID URI=$McpUrl, scope=$ScopeName, tokenVersion=2" -ForegroundColor Green

# --- A4: client secret (24 months) — printed ONCE -------------------------
$pw = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = 'claude-connector'
    EndDateTime = (Get-Date).AddMonths(24)
}

# --- Enterprise app (service principal) + B2 assignment required ----------
$sp = New-MgServicePrincipal -AppId $app.AppId
Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AppRoleAssignmentRequired:$true
Write-Host "B2  Service principal created; Assignment required = Yes" -ForegroundColor Green

# --- B1: security group + members -----------------------------------------
$group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
if (-not $group) {
    $group = New-MgGroup -DisplayName $GroupName -MailEnabled:$false `
        -MailNickname $GroupNick -SecurityEnabled:$true `
        -Description 'Read-only CLI access (SSH/Telnet) to managed network devices via the Claude MCP connector. Members can pull configs from any router, switch or firewall in the configured management ranges using the shared device credential.'
    Write-Host "B1  Created group $GroupName" -ForegroundColor Green
} else {
    Write-Host "B1  Reusing existing group $GroupName" -ForegroundColor Yellow
}
foreach ($m in ($resolved | Where-Object Id)) {
    try {
        New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $m.Id -ErrorAction Stop
        Write-Host "     added $($m.UPN)"
    } catch {
        Write-Host "     (skip $($m.UPN) — already a member)" -ForegroundColor Yellow
    }
}

# --- B3: assign the group to the app (default-access role) ----------------
# Group-to-app assignment needs Entra ID P1/P2. On the free tier it fails, so
# fall back to assigning each USER individually — same end result, more rows.
try {
    New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -BodyParameter @{
        principalId = $group.Id
        resourceId  = $sp.Id
        appRoleId   = $DefaultAccessRoleId
    } -ErrorAction Stop | Out-Null
    Write-Host "B3  Assigned group $GroupName to the app" -ForegroundColor Green
} catch {
    Write-Host "B3  Group assignment failed (needs Entra ID P1/P2): $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "B3  Falling back to per-user assignment..." -ForegroundColor Yellow
    foreach ($m in ($resolved | Where-Object Id)) {
        try {
            New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -BodyParameter @{
                principalId = $m.Id; resourceId = $sp.Id; appRoleId = $DefaultAccessRoleId
            } -ErrorAction Stop | Out-Null
            Write-Host "     assigned $($m.UPN)"
        } catch {
            Write-Host "     (skip $($m.UPN) — already assigned)" -ForegroundColor Yellow
        }
    }
    Write-Host "NOTE: with per-user assignment the GROUP is no longer the access gate." -ForegroundColor Yellow
    Write-Host "      Adding someone to $GroupName will NOT grant access — assign them here too." -ForegroundColor Yellow
}

# --- C1/C2: access-token lifetime policy (23:59:00) ------------------------
# Entra's default access token lifetime is ~60-90 minutes. For an MCP connector
# that is a re-auth prompt in the middle of someone's work. 23:59:00 is the
# maximum Entra will accept for an access token.
#
# Reused if a policy of this name already exists — appfolio-mcp created one, and
# a second policy with the same intent makes lifetimes impossible to reason
# about later. A service principal may hold only ONE token lifetime policy, so
# the attach is wrapped: failing it is a warning, not a dead script.
$PolicyName = 'MCP-AccessToken-24h'
$PolicyDef  = '{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"23:59:00"}}'

$policy = Get-MgPolicyTokenLifetimePolicy -All -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName -eq $PolicyName } | Select-Object -First 1
if (-not $policy) {
    $policy = New-MgPolicyTokenLifetimePolicy -BodyParameter @{
        displayName           = $PolicyName
        definition            = @($PolicyDef)
        isOrganizationDefault = $false
    }
    Write-Host "C1  Created token lifetime policy '$PolicyName' (23:59:00)" -ForegroundColor Green
} else {
    Write-Host "C1  Reusing existing token lifetime policy '$PolicyName'" -ForegroundColor Yellow
}

try {
    New-MgServicePrincipalTokenLifetimePolicyByRef -ServicePrincipalId $sp.Id -BodyParameter @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/policies/tokenLifetimePolicies/$($policy.Id)"
    } -ErrorAction Stop
    Write-Host "C2  Attached the 23:59:00 access-token lifetime to the app" -ForegroundColor Green
} catch {
    Write-Host "C2  Could not attach the token lifetime policy: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    Attach it by hand in Entra, or the connector falls back to the" -ForegroundColor Yellow
    Write-Host "    tenant default (~60-90 min) and will re-prompt mid-session." -ForegroundColor Yellow
}

# --- Output: what to put where --------------------------------------------
Write-Host "`n================ DONE — values for the server .env ================" -ForegroundColor Cyan
Write-Host "MCP_AUTH_ENABLED=true"
Write-Host "ENTRA_TENANT_ID=$ctxTenant"
Write-Host "ENTRA_CLIENT_ID=$($app.AppId)"
Write-Host "ENTRA_IDENTIFIER_URI=$McpUrl"
Write-Host "ENTRA_SCOPE_NAME=$ScopeName"
Write-Host "ENTRA_REQUIRED_SCOPES=$ScopeName"
Write-Host "MCP_BASE_URL=$($McpUrl -replace '/mcp$','')"
Write-Host "`n---- CLIENT SECRET (paste into Claude connector Advanced, NOT the server, NOT chat) ----" -ForegroundColor Magenta
Write-Host $pw.SecretText -ForegroundColor Magenta
Write-Host "`nThe tenant/client IDs above are safe to share; the secret is not." -ForegroundColor Cyan
Write-Host "It is shown ONCE. If you lose it, mint a new one in the app's Certificates & secrets." -ForegroundColor Cyan


