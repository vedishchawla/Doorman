import http from 'k6/http';
import { check } from 'k6';

const VUS = Number(__ENV.VUS || 50);
const DURATION = __ENV.DURATION || '20s';
const TARGET_URL = __ENV.TARGET_URL || 'https://localhost/backend-a/';
const ACCESS_TOKEN = __ENV.ACCESS_TOKEN || '';
const POSTURE_TOKEN = __ENV.POSTURE_TOKEN || '';

export const options = {
  insecureSkipTLSVerify: true,
  vus: VUS,
  duration: DURATION,
  thresholds: {
    http_req_duration: ['p(95)<12'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const headers = {};
  if (ACCESS_TOKEN) {
    headers['Authorization'] = `Bearer ${ACCESS_TOKEN}`;
  }
  if (POSTURE_TOKEN) {
    headers['X-Device-Posture'] = POSTURE_TOKEN;
  }

  const res = http.get(TARGET_URL, { headers });
  check(res, {
    'status is 200': (r) => r.status === 200,
    'latency under 12ms': (r) => r.timings.duration < 12,
  });
}
