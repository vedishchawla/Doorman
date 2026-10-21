package zt.authz_test

import data.zt.authz
import rego.v1

# ------------------------------------------------
# Helper: base input with good posture, allowed country, admin role, business hours
# ------------------------------------------------
base_input := {
	"user": "alice",
	"roles": ["admin"],
	"resource": "/",
	"method": "GET",
	"ip": "10.0.0.1",
	"geo": "IN",
	"time": "10:00",
	"device_posture": {
		"disk_encrypted": true,
		"firewall_on": true,
		"os_patch_age_days": 5,
	},
}

# ------------------------------------------------
# Admin full access
# ------------------------------------------------
test_admin_full_access if {
	authz.allow with input as base_input
}

test_admin_post_allowed if {
	authz.allow with input as object.union(base_input, {"method": "POST"})
}

test_admin_delete_allowed if {
	authz.allow with input as object.union(base_input, {"method": "DELETE"})
}

test_admin_admin_path_allowed if {
	authz.allow with input as object.union(base_input, {"resource": "/admin/settings"})
}

test_admin_admin_root_allowed if {
	authz.allow with input as object.union(base_input, {"resource": "/admin"})
}

# ------------------------------------------------
# Viewer: GET allowed
# ------------------------------------------------
test_viewer_get_allowed if {
	authz.allow with input as object.union(base_input, {"roles": ["viewer"]})
}

test_viewer_head_allowed if {
	authz.allow with input as object.union(base_input, {"roles": ["viewer"], "method": "HEAD"})
}

test_viewer_options_allowed if {
	authz.allow with input as object.union(base_input, {"roles": ["viewer"], "method": "OPTIONS"})
}

# ------------------------------------------------
# Viewer: POST denied
# ------------------------------------------------
test_viewer_post_denied if {
	not authz.allow with input as object.union(base_input, {"roles": ["viewer"], "method": "POST"})
}

test_viewer_post_denial_message if {
	d := authz.denials with input as object.union(base_input, {"roles": ["viewer"], "method": "POST"})
	some denial in d
	denial.rule_id == "viewer-method-denied"
}

# ------------------------------------------------
# Viewer: outside hours denied
# ------------------------------------------------
test_viewer_outside_hours_denied_early if {
	not authz.allow with input as object.union(base_input, {"roles": ["viewer"], "time": "08:00"})
}

test_viewer_outside_hours_denied_late if {
	not authz.allow with input as object.union(base_input, {"roles": ["viewer"], "time": "19:00"})
}

test_viewer_outside_hours_denial_message if {
	d := authz.denials with input as object.union(base_input, {"roles": ["viewer"], "time": "22:00"})
	some denial in d
	denial.rule_id == "viewer-time-restricted"
}

# ------------------------------------------------
# Viewer: inside hours allowed
# ------------------------------------------------
test_viewer_inside_hours_9am if {
	authz.allow with input as object.union(base_input, {"roles": ["viewer"], "time": "09:00"})
}

test_viewer_inside_hours_18 if {
	authz.allow with input as object.union(base_input, {"roles": ["viewer"], "time": "18:00"})
}

# Admin: NOT time-restricted (admin at 22:00 should be allowed)
test_admin_outside_hours_allowed if {
	authz.allow with input as object.union(base_input, {"time": "22:00"})
}

# ------------------------------------------------
# Blocked country denied
# ------------------------------------------------
test_blocked_country_denied if {
	not authz.allow with input as object.union(base_input, {"geo": "CN"})
}

test_blocked_country_denial_message if {
	d := authz.denials with input as object.union(base_input, {"geo": "RU"})
	some denial in d
	denial.rule_id == "geo-blocked"
}

# ------------------------------------------------
# Allowed country passes
# ------------------------------------------------
test_allowed_country_us if {
	authz.allow with input as object.union(base_input, {"geo": "US"})
}

test_allowed_country_gb if {
	authz.allow with input as object.union(base_input, {"geo": "GB"})
}

test_allowed_country_de if {
	authz.allow with input as object.union(base_input, {"geo": "DE"})
}

test_allowed_country_ca if {
	authz.allow with input as object.union(base_input, {"geo": "CA"})
}

# ------------------------------------------------
# Disk not encrypted denied
# ------------------------------------------------
test_disk_not_encrypted_denied if {
	not authz.allow with input as object.union(base_input, {
		"device_posture": {"disk_encrypted": false, "firewall_on": true, "os_patch_age_days": 5},
	})
}

test_disk_not_encrypted_denial_message if {
	d := authz.denials with input as object.union(base_input, {
		"device_posture": {"disk_encrypted": false, "firewall_on": true, "os_patch_age_days": 5},
	})
	some denial in d
	denial.rule_id == "disk-not-encrypted"
}

# ------------------------------------------------
# OS patch stale denied
# ------------------------------------------------
test_os_patch_stale_denied if {
	not authz.allow with input as object.union(base_input, {
		"device_posture": {"disk_encrypted": true, "firewall_on": true, "os_patch_age_days": 31},
	})
}

test_os_patch_stale_denial_message if {
	d := authz.denials with input as object.union(base_input, {
		"device_posture": {"disk_encrypted": true, "firewall_on": true, "os_patch_age_days": 45},
	})
	some denial in d
	denial.rule_id == "os-patch-stale"
}

# OS patch at exactly 30 should be allowed
test_os_patch_at_30_allowed if {
	authz.allow with input as object.union(base_input, {
		"device_posture": {"disk_encrypted": true, "firewall_on": true, "os_patch_age_days": 30},
	})
}

# ------------------------------------------------
# Good posture passes
# ------------------------------------------------
test_good_posture_passes if {
	authz.allow with input as base_input
}

# ------------------------------------------------
# Unknown role denied
# ------------------------------------------------
test_unknown_role_denied if {
	not authz.allow with input as object.union(base_input, {"roles": ["editor"]})
}

test_unknown_role_denial_message if {
	d := authz.denials with input as object.union(base_input, {"roles": ["editor"]})
	some denial in d
	denial.rule_id == "unknown-role"
}

test_empty_roles_denied if {
	not authz.allow with input as object.union(base_input, {"roles": []})
}

# ------------------------------------------------
# Viewer: /admin path denied
# ------------------------------------------------
test_viewer_admin_path_denied if {
	not authz.allow with input as object.union(base_input, {"roles": ["viewer"], "resource": "/admin/x"})
}

test_viewer_admin_root_denied if {
	not authz.allow with input as object.union(base_input, {"roles": ["viewer"], "resource": "/admin"})
}

test_viewer_admin_path_denial_message if {
	d := authz.denials with input as object.union(base_input, {"roles": ["viewer"], "resource": "/admin/users"})
	some denial in d
	denial.rule_id == "viewer-admin-path"
}

# ------------------------------------------------
# Multiple denials: deterministic output
# ------------------------------------------------
test_multiple_denials_sorted if {
	inp := object.union(base_input, {
		"roles": ["viewer"],
		"method": "POST",
		"time": "22:00",
		"device_posture": {"disk_encrypted": false, "firewall_on": true, "os_patch_age_days": 5},
	})
	d := authz.denials with input as inp
	count(d) >= 3
	# policy_id should be the first by sorted rule_id
	pid := authz.policy_id with input as inp
	pid == "disk-not-encrypted"
}

# ------------------------------------------------
# Firewall off denied
# ------------------------------------------------
test_firewall_off_denied if {
	not authz.allow with input as object.union(base_input, {
		"device_posture": {"disk_encrypted": true, "firewall_on": false, "os_patch_age_days": 5},
	})
}

test_firewall_off_denial_message if {
	d := authz.denials with input as object.union(base_input, {
		"device_posture": {"disk_encrypted": true, "firewall_on": false, "os_patch_age_days": 5},
	})
	some denial in d
	denial.rule_id == "firewall-off"
}

test_firewall_on_passes if {
	authz.allow with input as base_input
}
