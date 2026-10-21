import { describe, it, expect } from 'vitest';
import { evaluatePolicyLocally } from './api';
import { PolicyInput } from './types';

describe('evaluatePolicyLocally (mirroring zt.authz)', () => {
  const baseAdmin: PolicyInput = {
    user: 'alice',
    roles: ['admin'],
    resource: '/backend-a/data',
    method: 'GET',
    ip: '172.18.0.7',
    geo: 'IN',
    time: '14:00',
    device_posture: {
      disk_encrypted: true,
      firewall_on: true,
      os_patch_age_days: 5,
    },
  };

  it('allows compliant admin request', () => {
    const res = evaluatePolicyLocally(baseAdmin);
    expect(res.allow).toBe(true);
    expect(res.policy_id).toBe('');
    expect(res.reason).toBe('');
  });

  it('denies viewer accessing /admin path', () => {
    const input: PolicyInput = {
      ...baseAdmin,
      user: 'bob',
      roles: ['viewer'],
      resource: '/admin/config',
    };
    const res = evaluatePolicyLocally(input);
    expect(res.allow).toBe(false);
    expect(res.policy_id).toBe('viewer-admin-path');
    expect(res.reason).toBe('Denied: viewer cannot access /admin paths');
  });

  it('denies viewer outside business hours', () => {
    const input: PolicyInput = {
      ...baseAdmin,
      user: 'bob',
      roles: ['viewer'],
      time: '22:00',
    };
    const res = evaluatePolicyLocally(input);
    expect(res.allow).toBe(false);
    expect(res.policy_id).toBe('viewer-time-restricted');
    expect(res.reason).toBe('Denied: viewer access outside business hours 09:00-19:00');
  });

  it('denies viewer using POST method', () => {
    const input: PolicyInput = {
      ...baseAdmin,
      user: 'bob',
      roles: ['viewer'],
      method: 'POST',
    };
    const res = evaluatePolicyLocally(input);
    expect(res.allow).toBe(false);
    expect(res.policy_id).toBe('viewer-method-denied');
    expect(res.reason).toBe('Denied: viewer cannot use method POST');
  });

  it('denies unencrypted disk posture', () => {
    const input: PolicyInput = {
      ...baseAdmin,
      device_posture: {
        ...baseAdmin.device_posture,
        disk_encrypted: false,
      },
    };
    const res = evaluatePolicyLocally(input);
    expect(res.allow).toBe(false);
    expect(res.policy_id).toBe('disk-not-encrypted');
    expect(res.reason).toBe('Denied: device is not compliant: disk is not encrypted');
  });

  it('denies disabled firewall posture', () => {
    const input: PolicyInput = {
      ...baseAdmin,
      device_posture: {
        ...baseAdmin.device_posture,
        firewall_on: false,
      },
    };
    const res = evaluatePolicyLocally(input);
    expect(res.allow).toBe(false);
    expect(res.policy_id).toBe('firewall-off');
    expect(res.reason).toBe('Denied: device is not compliant: firewall is not enabled');
  });

  it('denies stale OS patch age over 30 days', () => {
    const input: PolicyInput = {
      ...baseAdmin,
      device_posture: {
        ...baseAdmin.device_posture,
        os_patch_age_days: 45,
      },
    };
    const res = evaluatePolicyLocally(input);
    expect(res.allow).toBe(false);
    expect(res.policy_id).toBe('os-patch-stale');
    expect(res.reason).toBe('Denied: OS patch age 45 days exceeds 30 day limit');
  });

  it('denies geo-blocked country', () => {
    const input: PolicyInput = {
      ...baseAdmin,
      geo: 'RU',
    };
    const res = evaluatePolicyLocally(input);
    expect(res.allow).toBe(false);
    expect(res.policy_id).toBe('geo-blocked');
    expect(res.reason).toBe('Denied: country RU is not in the allow list');
  });

  it('denies unknown role', () => {
    const input: PolicyInput = {
      ...baseAdmin,
      roles: ['guest'],
    };
    const res = evaluatePolicyLocally(input);
    expect(res.allow).toBe(false);
    expect(res.policy_id).toBe('unknown-role');
    expect(res.reason).toBe('Denied: no recognized role (admin or viewer)');
  });
});
