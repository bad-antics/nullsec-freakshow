#!/usr/bin/env node
// nullsec-kobold — HTTP Header Security Auditor (Node.js)
// The kobold inspects your HTTP defenses for weaknesses.
// Part of the nullsec freakshow suite.

const https = require('https');
const http = require('http');
const url = require('url');

const VERSION = '1.0.0';

const SECURITY_HEADERS = {
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)',
    severity: 'HIGH',
    desc: 'Forces HTTPS — prevents protocol downgrade attacks',
    check: (val) => {
      if (!val) return { pass: false, detail: 'Missing — no HSTS protection' };
      const maxAge = val.match(/max-age=(\d+)/);
      const age = maxAge ? parseInt(maxAge[1]) : 0;
      if (age < 31536000) return { pass: false, detail: `max-age too short (${age}s, need 31536000)` };
      const sub = val.includes('includeSubDomains');
      const preload = val.includes('preload');
      return { pass: true, detail: `max-age=${age}${sub ? ' +subdomains' : ''}${preload ? ' +preload' : ''}` };
    }
  },
  'content-security-policy': {
    name: 'Content-Security-Policy (CSP)',
    severity: 'HIGH',
    desc: 'Prevents XSS and injection attacks',
    check: (val) => {
      if (!val) return { pass: false, detail: 'Missing — no CSP protection' };
      const unsafe = [];
      if (val.includes("'unsafe-inline'")) unsafe.push('unsafe-inline');
      if (val.includes("'unsafe-eval'")) unsafe.push('unsafe-eval');
      if (val.includes('*')) unsafe.push('wildcard source');
      if (unsafe.length) return { pass: false, detail: `Weak CSP: ${unsafe.join(', ')}` };
      return { pass: true, detail: `CSP present (${val.length} chars)` };
    }
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    severity: 'MEDIUM',
    desc: 'Prevents MIME-type sniffing',
    check: (val) => {
      if (!val) return { pass: false, detail: 'Missing — MIME sniffing possible' };
      return val.toLowerCase() === 'nosniff'
        ? { pass: true, detail: 'nosniff ✓' }
        : { pass: false, detail: `Unexpected value: ${val}` };
    }
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    severity: 'MEDIUM',
    desc: 'Prevents clickjacking via iframes',
    check: (val) => {
      if (!val) return { pass: false, detail: 'Missing — clickjacking possible' };
      const v = val.toUpperCase();
      if (v === 'DENY' || v === 'SAMEORIGIN') return { pass: true, detail: v };
      return { pass: false, detail: `Weak value: ${val}` };
    }
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    severity: 'LOW',
    desc: 'Legacy XSS filter (deprecated but informative)',
    check: (val) => {
      if (!val) return { pass: true, detail: 'Absent (OK — modern browsers ignore it)' };
      return { pass: true, detail: val };
    }
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    severity: 'MEDIUM',
    desc: 'Controls referrer information leakage',
    check: (val) => {
      if (!val) return { pass: false, detail: 'Missing — full referrer may leak' };
      const safe = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
      return safe.includes(val.toLowerCase())
        ? { pass: true, detail: val }
        : { pass: false, detail: `Weak policy: ${val}` };
    }
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    severity: 'MEDIUM',
    desc: 'Controls browser feature access (camera, mic, geolocation)',
    check: (val) => {
      if (!val) return { pass: false, detail: 'Missing — all browser features allowed' };
      return { pass: true, detail: `Present (${val.length} chars)` };
    }
  },
  'x-permitted-cross-domain-policies': {
    name: 'X-Permitted-Cross-Domain-Policies',
    severity: 'LOW',
    desc: 'Controls Flash/PDF cross-domain access',
    check: (val) => {
      if (!val) return { pass: false, detail: 'Missing' };
      return val.toLowerCase() === 'none'
        ? { pass: true, detail: 'none ✓' }
        : { pass: false, detail: val };
    }
  }
};

const DANGEROUS_HEADERS = {
  'server': 'Server version disclosure',
  'x-powered-by': 'Technology stack disclosure',
  'x-aspnet-version': 'ASP.NET version disclosure',
  'x-aspnetmvc-version': 'ASP.NET MVC version disclosure',
  'x-generator': 'Generator disclosure',
  'x-drupal-cache': 'Drupal disclosure',
  'x-varnish': 'Varnish cache disclosure',
};

function fetchHeaders(targetUrl) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const mod = parsed.protocol === 'https:' ? https : http;

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'HEAD',
      timeout: 10000,
      rejectUnauthorized: false,
      headers: { 'User-Agent': 'nullsec-kobold/1.0' }
    };

    const req = mod.request(options, (res) => {
      resolve({
        statusCode: res.statusCode,
        headers: res.headers,
        url: targetUrl
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

async function auditUrl(targetUrl) {
  console.log(`\n🔧 KOBOLD — HTTP Header Security Audit\n`);
  console.log(`   Target: ${targetUrl}\n`);

  let result;
  try {
    result = await fetchHeaders(targetUrl);
  } catch (e) {
    console.error(`  ❌ Connection failed: ${e.message}\n`);
    process.exit(1);
  }

  console.log(`   Status: ${result.statusCode}`);
  console.log(`   ${'─'.repeat(50)}\n`);

  let passed = 0, failed = 0, warnings = 0;

  // Check security headers
  console.log('  🛡️  Security Headers:\n');
  for (const [header, config] of Object.entries(SECURITY_HEADERS)) {
    const val = result.headers[header];
    const check = config.check(val);

    if (check.pass) {
      console.log(`    ✅ ${config.name}`);
      console.log(`       ${check.detail}`);
      passed++;
    } else {
      const icon = config.severity === 'HIGH' ? '🔴' : '🟡';
      console.log(`    ${icon} ${config.name} [${config.severity}]`);
      console.log(`       ${check.detail}`);
      failed++;
    }
  }

  // Check info disclosure headers
  console.log('\n  📡 Information Disclosure:\n');
  for (const [header, desc] of Object.entries(DANGEROUS_HEADERS)) {
    const val = result.headers[header];
    if (val) {
      console.log(`    ⚠️  ${header}: ${val}`);
      console.log(`       ${desc}`);
      warnings++;
    }
  }
  if (warnings === 0) {
    console.log('    ✅ No information disclosure headers found');
  }

  // Cookie security
  const setCookie = result.headers['set-cookie'];
  if (setCookie) {
    console.log('\n  🍪 Cookie Security:\n');
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const cookie of cookies) {
      const name = cookie.split('=')[0];
      const flags = [];
      if (!cookie.toLowerCase().includes('secure')) flags.push('missing Secure');
      if (!cookie.toLowerCase().includes('httponly')) flags.push('missing HttpOnly');
      if (!cookie.toLowerCase().includes('samesite')) flags.push('missing SameSite');
      if (flags.length) {
        console.log(`    🟡 ${name}: ${flags.join(', ')}`);
        warnings++;
      } else {
        console.log(`    ✅ ${name}: Secure, HttpOnly, SameSite`);
      }
    }
  }

  // Score
  const total = passed + failed;
  const score = total > 0 ? Math.round((passed / total) * 100) : 0;
  const grade = score >= 90 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : score >= 30 ? 'D' : 'F';

  console.log(`\n  ${'─'.repeat(50)}`);
  console.log(`  📊 Score: ${score}% (${grade}) — ${passed} passed, ${failed} failed, ${warnings} warnings\n`);
}

async function auditMultiple(urls) {
  for (const u of urls) {
    await auditUrl(u);
  }
}

function printHelp() {
  console.log(`
🔧 nullsec-kobold v${VERSION} — HTTP Header Security Auditor (Node.js)
   Part of the nullsec freakshow suite.

Usage:
  kobold <url>               Audit a single URL
  kobold <url1> <url2> ...   Audit multiple URLs

Examples:
  kobold https://example.com
  kobold https://google.com https://github.com
  kobold http://localhost:8080
`);
}

// Main
const args = process.argv.slice(2);
if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  printHelp();
} else {
  const urls = args.map(a => {
    if (!a.startsWith('http://') && !a.startsWith('https://')) return 'https://' + a;
    return a;
  });
  auditMultiple(urls).catch(e => console.error(`Error: ${e.message}`));
}
