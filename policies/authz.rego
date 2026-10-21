package zt.authz

import rego.v1

# ------------------------------------------------
# Default: deny unless explicitly granted
# ------------------------------------------------
default allow := false

# ------------------------------------------------
# Collect denials into a set
# ------------------------------------------------

# Geo-blocking: country must be in the allow list
denials contains {"rule_id": "geo-blocked", "message": concat("", ["Denied: country ", input.geo, " is not in the allow list"])} if {
	not input.geo in data.allowed_countries
}

# Device posture: disk must be encrypted
denials contains {"rule_id": "disk-not-encrypted", "message": "Denied: disk is not encrypted"} if {
	input.device_posture.disk_encrypted == false
}

# Device posture: firewall must be enabled
denials contains {"rule_id": "firewall-off", "message": "Denied: firewall is not enabled"} if {
	input.device_posture.firewall_on == false
}

# Device posture: OS patch age must be ≤ 30 days
denials contains {"rule_id": "os-patch-stale", "message": concat("", ["Denied: OS patch age ", format_int(input.device_posture.os_patch_age_days, 10), " days exceeds 30 day limit"])} if {
	input.device_posture.os_patch_age_days > 30
}

# Viewer: denied outside business hours (09:00–19:00)
denials contains {"rule_id": "viewer-time-restricted", "message": "Denied: viewer access outside business hours 09:00-19:00"} if {
	is_viewer
	not is_admin
	hour := to_number(split(input.time, ":")[0])
	not in_business_hours(hour)
}

# Viewer: read-only methods only
denials contains {"rule_id": "viewer-method-denied", "message": concat("", ["Denied: viewer cannot use method ", input.method])} if {
	is_viewer
	not is_admin
	not input.method in {"GET", "HEAD", "OPTIONS"}
}

# Viewer: denied access to /admin paths
denials contains {"rule_id": "viewer-admin-path", "message": "Denied: viewer cannot access /admin paths"} if {
	is_viewer
	not is_admin
	startswith(input.resource, "/admin")
}

# Unknown role: no recognized role found
denials contains {"rule_id": "unknown-role", "message": "Denied: no recognized role (admin or viewer)"} if {
	not is_admin
	not is_viewer
}

# ------------------------------------------------
# Positive grants
# ------------------------------------------------

# Allow if no denials and user has a recognized role grant
allow if {
	count(denials) == 0
	role_granted
}

# Admin: all methods and all paths
role_granted if {
	is_admin
}

# Viewer: GET/HEAD/OPTIONS, not /admin
role_granted if {
	is_viewer
	not is_admin
	input.method in {"GET", "HEAD", "OPTIONS"}
	not startswith(input.resource, "/admin")
}

# ------------------------------------------------
# Helpers
# ------------------------------------------------

is_admin if {
	some role in input.roles
	role == "admin"
}

is_viewer if {
	some role in input.roles
	role == "viewer"
}

in_business_hours(hour) if {
	hour >= 9
	hour < 19
}

# ------------------------------------------------
# Output: deterministic reason from sorted denials
# ------------------------------------------------

sorted_denials := sort(denials)

reason := sorted_denials[0].message if {
	count(sorted_denials) > 0
}

reason := "" if {
	count(sorted_denials) == 0
}

policy_id := sorted_denials[0].rule_id if {
	count(sorted_denials) > 0
}

policy_id := "" if {
	count(sorted_denials) == 0
}
