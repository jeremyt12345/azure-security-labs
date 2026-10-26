# Entra ID App Registration Breach — Kill Chain Investigation

**Type:** Cloud identity incident investigation (lab)
**Platform:** Microsoft Azure / Entra ID
**Source:** Mad Hat Labs — Module 1, Chapter 2 (Entra ID)
**Skills:** Entra ID app registrations, OAuth 2.0, service principals, Microsoft Graph permissions, consent phishing, KQL detection, PowerShell / Microsoft Graph auditing

> Lab environment only. Flags and step-by-step lab content are intentionally left out to respect the course.

---

## Summary

An attacker compromised a Microsoft 365 tenant entirely through the identity plane. No exploits, no malware, and no alerts fired. Using read-only access to directory applications, I reconstructed the full kill chain from configuration left behind on a single legacy app registration.

**Key takeaway:** A review of privileged roles (Global Admin, Privileged Role Admin) would have missed this attack completely. The risk lived in app ownership, credentials, and permissions, so the whole permission chain has to be audited, not just direct role assignments.

---

## Scenario

- A legacy internal connector app was flagged as tampered with.
- The app held **application permissions on Microsoft Graph with admin consent** (`Directory.Read.All`, `User.ReadWrite.All`), giving it tenant-wide capability.
- A standard user had mistakenly been left as an **Owner** of the app.

---

## Kill Chain

| Stage | What the attacker did | Where the evidence was | Why it worked |
|---|---|---|---|
| **1. Entry** | Phished a user with a fake login page and stole the session token issued after MFA (AiTM) | App notes / sign-in context | The stolen token carried an MFA-satisfied claim, so Conditional Access saw a normal sign-in |
| **2. Escalate** | Used the user's Owner rights to add a client secret to the legacy app | Certificates & secrets | Client credentials flow let them act as the app's service principal with its Graph permissions, no human sign-in needed. The secret was set to expire nearly a century out |
| **3. Pivot** | Registered a rogue app and added its service principal as an **Owner** of the legacy app | Owners blade | By default users can register apps. A second owner lets the attacker mint new secrets even if the original is rotated, creating a "shadow admin" |
| **4. Persist** | Added a custom scope under **Expose an API** on the legacy app | Expose an API blade | Gave the attacker a backup access path that survives credential rotation |
| **5. Loot** | Added an attacker-controlled **redirect URI** to the rogue app to harvest authorization codes via consent phishing | Authentication blade (rogue app) | When a user consents, Entra ID creates an OAuth2PermissionGrant. Password resets, session revocation, and MFA do **not** remove it. Classic confused-deputy setup |

---

## MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Phishing | T1566 |
| Steal Web Session Cookie | T1539 |
| Use Alternate Authentication Material: Application Access Token | T1550.001 |
| Account Manipulation: Additional Cloud Credentials | T1098.001 |
| Valid Accounts: Cloud Accounts | T1078.004 |
| Steal Application Access Token (consent phishing) | T1528 |

---

## Detection

### KQL — risky app registration changes (Sentinel / Log Analytics `AuditLogs`)

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any (
    "Certificates and secrets management",
    "Add service principal credentials",
    "Add owner to application",
    "Add owner to service principal",
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to service principal"
  )
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Target = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, Target, Result
| sort by TimeGenerated desc
```

**What to alert on:**
- New credentials added to an app by a non-admin user
- A service principal added as an owner of another app
- Consent grants to apps with high-privilege or unfamiliar scopes
- New redirect URIs pointing to external, non-company domains

---

## Audit Script — app registration hygiene (Microsoft Graph PowerShell)

```powershell
Connect-MgGraph -Scopes "Application.Read.All"

$apps = Get-MgApplication -All -Property Id,DisplayName,AppId,PasswordCredentials,KeyCredentials

foreach ($app in $apps) {
    $owners = Get-MgApplicationOwner -ApplicationId $app.Id |
        ForEach-Object { $_.AdditionalProperties.displayName }

    foreach ($secret in $app.PasswordCredentials) {
        $years = [math]::Round((New-TimeSpan -Start (Get-Date) -End $secret.EndDateTime).TotalDays / 365, 1)
        [PSCustomObject]@{
            App          = $app.DisplayName
            AppId        = $app.AppId
            SecretName   = $secret.DisplayName
            ExpiresOn    = $secret.EndDateTime
            YearsLeft    = $years
            LongLived    = $years -gt 2
            Owners       = ($owners -join "; ")
        }
    }
} | Sort-Object YearsLeft -Descending | Export-Csv .\AppSecretAudit.csv -NoTypeInformation
```

Flags long-lived secrets and lists owners for every app registration so unexpected owners (including service principals) stand out.

---

## Prevention / Hardening

- **Restrict app registration:** set "Users can register applications" to **No**.
- **Restrict user consent:** allow consent only for verified publishers with low-risk permissions, and enable the **admin consent workflow**.
- **Least privilege on Graph permissions:** review application permissions with admin consent and remove anything not required.
- **Credential lifetime policy:** enforce short secret lifetimes, or prefer certificates and managed identities over client secrets.
- **Review app owners regularly:** treat app ownership as privileged access and include it in access reviews.
- **Token theft defenses:** phishing-resistant MFA, compliant-device Conditional Access, and token protection where supported.
- **Monitor:** alert on the audit log events above in Sentinel.

---

## Lessons Learned

1. Identity is the perimeter. App registration properties grant access the same way firewall rules do.
2. A privileged-role review is not enough. App ownership and service principals create hidden "shadow admins."
3. OAuth consent grants survive password resets, session revocation, and MFA, so they must be checked during every account compromise investigation.
4. Long-lived secrets and unreviewed owners are common defaults that attackers rely on.

---

## Screenshots


### 1. API permissions — tenant-wide Graph access with admin consent

<img width="1912" height="914" alt="image" src="https://github.com/user-attachments/assets/d6e9614c-b978-47a9-85e0-a0b9ebe71057" />



- Client Secret-Expiry

- <img width="1912" height="914" alt="image" src="https://github.com/user-attachments/assets/6c6ad11d-d6c2-47e7-b22c-9bb378c167db" />

- `screenshots/03-owners.png`
- `screenshots/04-expose-an-api.png`
- `screenshots/05-redirect-uri.png`
