# Fraud Detection Scoring Guide

## Overview

The fraud detection system uses a layered approach with multiple signals to calculate a risk score (0-100). Each signal contributes points to the total score based on its severity.

## Scoring Breakdown

### Layer 1: Email Syntax Validation
- **Score:** N/A (Rejects request if invalid)
- **Description:** Basic email format validation
- **Action:** Throws error if syntax is invalid

### Layer 2: Disposable Domain Detection
- **Score:** +90 points
- **Description:** Checks if email domain is a known temporary/disposable provider
- **Examples:** mailinator.com, guerrillamail.com, tempmail.com
- **Signal:** `is_disposable: true`

### Layer 3: MX Record Verification
- **Score:** +100 points (max score)
- **Description:** Verifies domain has valid Mail Exchange records
- **Impact:** No MX = domain can't receive email = likely fake
- **Signal:** `mx_found: false`

### Layer 4: Entropy Analysis
- **Score:** +30 points (if entropy > 4.5)
- **Description:** Detects randomly generated email local parts
- **Examples:** 
  - Low entropy (normal): `john.doe` → 3.2
  - High entropy (random): `a8f3k2ds` → 5.1
- **Signal:** `entropy_score: <float>`

### Layer 5: Velocity Check
- **Score:** +40 points
- **Description:** Detects rapid signup attempts from same IP or domain
- **Threshold:** >10 signups per hour from same IP
- **Signal:** `velocity_breach: true`

### Layer 6: VPN/Proxy Detection ✨ NEW
- **Score:** 
  - +50 points (VPN or Proxy)
  - +30 points (Datacenter only)
- **Description:** Identifies non-residential IP addresses
- **Detection:** Checks IP against known VPN/proxy/datacenter ranges
- **Signals:** 
  - `is_vpn: true`
  - `is_proxy: true`
  - `is_datacenter: true`
  - `ip_country: "USA"`

### Layer 7: Domain Age Verification ✨ NEW
- **Score:** +60 points
- **Description:** Flags newly registered domains (<30 days old)
- **Rationale:** Fraudsters often use fresh domains
- **Detection:** WHOIS lookup for domain registration date
- **Signals:**
  - `is_new_domain: true`
  - `domain_age_days: 5`

### Layer 8: Pattern Detection ✨ NEW
- **Score:** 
  - +40 points (Sequential pattern: `user1`, `user2`)
  - +25 points (Number suffix: `john123`)
  - +35 points (Similar to recent signup)
- **Description:** Detects automated account creation patterns
- **Methods:**
  - Sequential: Emails like `test1@`, `test2@`
  - Number suffix: 2+ digits at end (e.g., `name456@`)
  - Similarity: 85%+ match to recent email (Levenshtein distance)
- **Signals:**
  - `is_sequential: true`
  - `has_number_suffix: true`
  - `is_similar_to_recent: true`
  - `pattern_detected: "SEQUENTIAL" | "NUMBER_SUFFIX" | "SIMILAR_TO_RECENT"`

## Risk Levels

| Score Range | Level | Action | Description |
|-------------|-------|--------|-------------|
| 0 - 30 | **LOW** | ALLOW | Clean signup, proceed normally |
| 31 - 70 | **MEDIUM** | CHALLENGE | Suspicious signals detected, require additional verification (CAPTCHA, email OTP) |
| 71+ | **HIGH** | BLOCK | Strong evidence of fraud, reject signup |

## Example Scenarios

### Scenario 1: Clean User
- Email: `john.doe@gmail.com`
- IP: Residential ISP, USA
- **Signals Triggered:** None
- **Total Score:** 0
- **Result:** ✅ LOW - ALLOW

### Scenario 2: Suspicious but not blocking
- Email: `testuser123@yahoo.com`
- IP: Datacenter IP
- **Signals Triggered:**
  - Number suffix +25
  - Datacenter IP +30
- **Total Score:** 55
- **Result:** ⚠️ MEDIUM - CHALLENGE

### Scenario 3: Clear Fraud
- Email: `a8f3k2@newdomain.com`
- IP: VPN
- Domain: Registered 5 days ago
- **Signals Triggered:**
  - High entropy +30
  - VPN detected +50
  - New domain +60
- **Total Score:** 100 (capped)
- **Result:** 🚫 HIGH - BLOCK

### Scenario 4: Disposable Email
- Email: `anything@mailinator.com`
- **Signals Triggered:**
  - Disposable domain +90
- **Total Score:** 90
- **Result:** 🚫 HIGH - BLOCK

### Scenario 5: Coordinated Attack
- Email: `user5@example.com` (similar to recent `user4@example.com`)
- IP: Same IP as 15 previous signups
- **Signals Triggered:**
  - Sequential pattern +40
  - Similar to recent +35
  - Velocity breach +40
- **Total Score:** 100 (capped)
- **Result:** 🚫 HIGH - BLOCK

## Adjusting Thresholds

To customize the scoring for your use case, modify these values in `risk_engine.py`:

```python
# Disposable domain
score += 90  # Line ~115

# No MX record
score += 100  # Line ~121

# High entropy
if entropy > 4.5:  # Adjust threshold here
    score += 30  # Line ~129

# Velocity breach
score += 40  # Line ~135

# VPN/Proxy
score += 50  # Line ~142
# Datacenter only
score += 30  # Line ~145

# New domain
score += 60  # Line ~154

# Sequential pattern
score += 40  # Line ~165
# Number suffix
score += 25  # Line ~167
# Similar to recent
score += 35  # Line ~171
```

## Best Practices

1. **Start Conservative:** Use the MEDIUM tier for challenges rather than outright blocks
2. **Monitor False Positives:** Track legitimate users being flagged
3. **Whitelist Known Good:** Bypass checks for trusted IP ranges or domains
4. **Adjust Gradually:** Tune score weights based on your fraud patterns
5. **Combine Signals:** Multiple weak signals = strong fraud indicator
6. **Log Everything:** Use logs to identify new fraud patterns

## API Response Example

```json
{
  "email": "user123@newsite.com",
  "normalized_email": "user123@newsite.com",
  "risk_summary": {
    "score": 85,
    "level": "HIGH",
    "action": "BLOCK"
  },
  "signals": {
    "is_disposable": false,
    "mx_found": true,
    "velocity_breach": false,
    "entropy_score": 3.2,
    "is_alias": false,
    "is_vpn": false,
    "is_proxy": false,
    "is_datacenter": false,
    "ip_country": "United States",
    "domain_age_days": 3,
    "is_new_domain": true,
    "pattern_detected": "NUMBER_SUFFIX",
    "is_sequential": false,
    "has_number_suffix": true,
    "is_similar_to_recent": false
  }
}
```
