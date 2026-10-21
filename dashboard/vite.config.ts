import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'node:fs';
import path from 'node:path';

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'audit-and-bench-api-server',
      configureServer(server) {
        // Serve /api/audit
        server.middlewares.use('/api/audit', (req, res) => {
          const url = new URL(req.url || '', `http://${req.headers.host}`);
          const filterUser = url.searchParams.get('user') || '';
          const filterDecision = url.searchParams.get('decision') || '';
          const filterResource = url.searchParams.get('resource') || '';

          const logPath = path.resolve(__dirname, '../audit-logs/audit.jsonl');
          let entries: any[] = [];

          if (fs.existsSync(logPath)) {
            const lines = fs.readFileSync(logPath, 'utf-8').trim().split('\n');
            for (let i = lines.length - 1; i >= 0; i--) {
              const line = lines[i].trim();
              if (!line) continue;
              try {
                const item = JSON.parse(line);
                if (filterUser && item.user !== filterUser) continue;
                if (filterDecision && item.decision !== filterDecision) continue;
                if (filterResource && item.resource !== filterResource) continue;
                entries.push(item);
              } catch (e) {
                // skip corrupted lines
              }
            }
          }

          res.setHeader('Content-Type', 'application/json');
          res.setHeader('Access-Control-Allow-Origin', '*');
          res.end(JSON.stringify(entries));
        });

        // Serve /bench/results.csv
        server.middlewares.use('/bench/results.csv', (_req, res) => {
          const csvPath = path.resolve(__dirname, '../bench/results.csv');
          if (fs.existsSync(csvPath)) {
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.end(fs.readFileSync(csvPath, 'utf-8'));
          } else {
            res.statusCode = 404;
            res.end('results.csv not found');
          }
        });

        // Serve /api/policy/eval
        server.middlewares.use('/api/policy/eval', (req, res) => {
          if (req.method !== 'POST') {
            res.statusCode = 405;
            res.end('Method not allowed');
            return;
          }

          let body = '';
          req.on('data', chunk => {
            body += chunk;
          });

          req.on('end', () => {
            try {
              const parsed = JSON.parse(body || '{}');
              const input = parsed.input || parsed;

              // Read policies/data.json for allowed_countries
              const dataPath = path.resolve(__dirname, '../policies/data.json');
              let allowedCountries = ['IN', 'US', 'GB', 'DE', 'SG'];
              if (fs.existsSync(dataPath)) {
                try {
                  const dataJson = JSON.parse(fs.readFileSync(dataPath, 'utf-8'));
                  if (Array.isArray(dataJson.allowed_countries)) {
                    allowedCountries = dataJson.allowed_countries;
                  }
                } catch (e) {}
              }

              // Evaluate denials per zt.authz
              const denials: { rule_id: string; message: string }[] = [];
              const roles: string[] = Array.isArray(input.roles) ? input.roles : [];
              const isAdmin = roles.includes('admin');
              const isViewer = roles.includes('viewer');

              // Geo
              if (!input.geo || !allowedCountries.includes(input.geo)) {
                denials.push({
                  rule_id: 'geo-blocked',
                  message: `Denied: country ${input.geo || ''} is not in the allow list`,
                });
              }

              // Posture
              const posture = input.device_posture;
              if (!posture || posture.disk_encrypted === false) {
                denials.push({
                  rule_id: 'disk-not-encrypted',
                  message: 'Denied: device is not compliant: disk is not encrypted',
                });
              }
              if (!posture || posture.firewall_on === false) {
                denials.push({
                  rule_id: 'firewall-off',
                  message: 'Denied: device is not compliant: firewall is not enabled',
                });
              }
              if (!posture || (typeof posture.os_patch_age_days === 'number' && posture.os_patch_age_days > 30)) {
                const days = posture ? posture.os_patch_age_days : 0;
                denials.push({
                  rule_id: 'os-patch-stale',
                  message: `Denied: OS patch age ${days} days exceeds 30 day limit`,
                });
              }

              // Roles and permissions
              if (!isAdmin && !isViewer) {
                denials.push({
                  rule_id: 'unknown-role',
                  message: 'Denied: no recognized role (admin or viewer)',
                });
              } else if (isViewer && !isAdmin) {
                // Business hours
                if (input.time) {
                  const hour = parseInt(input.time.split(':')[0], 10);
                  if (isNaN(hour) || hour < 9 || hour >= 19) {
                    denials.push({
                      rule_id: 'viewer-time-restricted',
                      message: 'Denied: viewer access outside business hours 09:00-19:00',
                    });
                  }
                }
                // Methods
                const method = (input.method || '').toUpperCase();
                if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
                  denials.push({
                    rule_id: 'viewer-method-denied',
                    message: `Denied: viewer cannot use method ${method}`,
                  });
                }
                // Resource
                const resPath = input.resource || '';
                if (resPath.startsWith('/admin')) {
                  denials.push({
                    rule_id: 'viewer-admin-path',
                    message: 'Denied: viewer cannot access /admin paths',
                  });
                }
              }

              // Deterministic sorting of denials
              denials.sort((a, b) => a.rule_id.localeCompare(b.rule_id));

              let allow = false;
              if (denials.length === 0) {
                if (isAdmin) allow = true;
                else if (isViewer) {
                  const m = (input.method || '').toUpperCase();
                  const r = input.resource || '';
                  if (['GET', 'HEAD', 'OPTIONS'].includes(m) && !r.startsWith('/admin')) {
                    allow = true;
                  }
                }
              }

              const result = {
                allow,
                policy_id: denials.length > 0 ? denials[0].rule_id : '',
                reason: denials.length > 0 ? denials[0].message : '',
                denials,
              };

              res.setHeader('Content-Type', 'application/json');
              res.setHeader('Access-Control-Allow-Origin', '*');
              res.end(JSON.stringify({ result }));
            } catch (err: any) {
              res.statusCode = 400;
              res.end(JSON.stringify({ error: err.message || 'Invalid JSON' }));
            }
          });
        });
      },
    },
  ],
  server: {
    port: 3000,
  },
});
