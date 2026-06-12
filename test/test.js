#!/usr/bin/env node
'use strict';

const { analyze, parseDockerfile, checkBaseImage, checkRun, checkCopyAdd, analyzeGlobal } = require('../src/analyzer');
const assert = require('assert');

let passed = 0, failed = 0;

function test(name, fn) {
  try { fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.log(`  ✗ ${name}\n    ${e.message}`); }
}

// --- parseDockerfile ---
test('parses simple FROM', () => {
  const insts = parseDockerfile('FROM node:18\nRUN echo hi');
  assert.equal(insts.length, 2);
  assert.equal(insts[0].instruction, 'FROM');
});

test('handles comments and blanks', () => {
  const insts = parseDockerfile('# comment\n\nFROM alpine\n  \nRUN x');
  assert.equal(insts.length, 2);
});

test('joins multiline RUN', () => {
  const dockerfile = 'RUN apt-get update \\\n  && apt-get install -y curl';
  const insts = parseDockerfile(dockerfile);
  assert.equal(insts.length, 1);
  assert.ok(insts[0].args.includes('&&'));
});

// --- checkBaseImage ---
test('warns on :latest tag', () => {
  const f = checkBaseImage({ instruction: 'FROM', args: 'ubuntu:latest', startLine: 1 });
  assert.ok(f.some(x => x.rule === 'DL3001'));
});

test('warns on no tag', () => {
  const f = checkBaseImage({ instruction: 'FROM', args: 'node', startLine: 1 });
  assert.ok(f.some(x => x.rule === 'DL3001'));
});

test('ok on pinned tag', () => {
  const f = checkBaseImage({ instruction: 'FROM', args: 'node:18-alpine', startLine: 1 });
  assert.ok(!f.some(x => x.rule === 'DL3001'));
});

test('ok on sha256 digest', () => {
  const f = checkBaseImage({ instruction: 'FROM', args: 'node@sha256:abc123', startLine: 1 });
  assert.ok(!f.some(x => x.rule === 'DL3001'));
});

test('info for full OS image', () => {
  const f = checkBaseImage({ instruction: 'FROM', args: 'ubuntu:22.04', startLine: 1 });
  assert.ok(f.some(x => x.rule === 'DL3002' && x.severity === 'info'));
});

// --- checkRun ---
test('warns apt-get without --no-install-recommends', () => {
  const f = checkRun({ instruction: 'RUN', args: 'apt-get install -y nodejs', startLine: 3 });
  assert.ok(f.some(x => x.rule === 'DL3014'));
});

test('ok apt-get with --no-install-recommends', () => {
  const f = checkRun({ instruction: 'RUN', args: 'apt-get install -y --no-install-recommends nodejs', startLine: 3 });
  assert.ok(!f.some(x => x.rule === 'DL3014'));
});

test('error on apt-get install without -y', () => {
  const f = checkRun({ instruction: 'RUN', args: 'apt-get install nodejs', startLine: 3 });
  assert.ok(f.some(x => x.rule === 'DL3015' && x.severity === 'error'));
});

test('error on sudo', () => {
  const f = checkRun({ instruction: 'RUN', args: 'sudo apt-get update', startLine: 5 });
  assert.ok(f.some(x => x.rule === 'DL3004'));
});

test('warns on curl | sh', () => {
  const f = checkRun({ instruction: 'RUN', args: 'curl https://x.com/install.sh | sh', startLine: 4 });
  assert.ok(f.some(x => x.rule === 'DL4001'));
});

// --- checkCopyAdd ---
test('info on ADD instead of COPY', () => {
  const f = checkCopyAdd({ instruction: 'ADD', args: 'app.js /app/', startLine: 6 });
  assert.ok(f.some(x => x.rule === 'DL3010'));
});

test('ok on ADD for tar', () => {
  const f = checkCopyAdd({ instruction: 'ADD', args: 'app.tar.gz /app/', startLine: 6 });
  assert.ok(!f.some(x => x.rule === 'DL3010'));
});

test('ok on ADD for URL', () => {
  const f = checkCopyAdd({ instruction: 'ADD', args: 'https://x.com/f.tar.gz /app/', startLine: 6 });
  assert.ok(!f.some(x => x.rule === 'DL3010'));
});

// --- analyzeGlobal ---
test('error on no FROM', () => {
  const f = analyzeGlobal([{ instruction: 'RUN', args: 'echo hi', startLine: 1 }]);
  assert.ok(f.some(x => x.rule === 'DL3000'));
});

test('warns no USER', () => {
  const f = analyzeGlobal([{ instruction: 'FROM', args: 'node:18', startLine: 1 }]);
  assert.ok(f.some(x => x.rule === 'DL3002'));
});

test('info on no HEALTHCHECK', () => {
  const f = analyzeGlobal([{ instruction: 'FROM', args: 'node:18', startLine: 1 }, { instruction: 'USER', args: 'app', startLine: 2 }]);
  assert.ok(f.some(x => x.rule === 'DL3003'));
});

test('info on privileged port', () => {
  const f = analyzeGlobal([
    { instruction: 'FROM', args: 'node:18', startLine: 1 },
    { instruction: 'USER', args: 'app', startLine: 2 },
    { instruction: 'EXPOSE', args: '80', startLine: 3 },
  ]);
  assert.ok(f.some(x => x.rule === 'DL3006'));
});

test('ok on non-privileged port', () => {
  const f = analyzeGlobal([
    { instruction: 'FROM', args: 'node:18', startLine: 1 },
    { instruction: 'USER', args: 'app', startLine: 2 },
    { instruction: 'EXPOSE', args: '8080', startLine: 3 },
  ]);
  assert.ok(!f.some(x => x.rule === 'DL3006'));
});

// --- full analyze ---
test('full analyze returns sorted findings', () => {
  const dockerfile = `FROM ubuntu
RUN apt-get install nodejs
ADD app.js /app/
EXPOSE 80`;
  const f = analyze(dockerfile);
  assert.ok(f.length > 3);
  // errors first
  const firstError = f.findIndex(x => x.severity === 'error');
  const firstWarn = f.findIndex(x => x.severity === 'warning');
  assert.ok(firstError < firstWarn || firstWarn === -1);
});

test('clean dockerfile passes', () => {
  const dockerfile = `FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s CMD wget -q --spider http://localhost:3000/ || exit 1
CMD ["node", "server.js"]`;
  const f = analyze(dockerfile);
  assert.equal(f.filter(x => x.severity === 'error').length, 0);
});

// --- summary ---
console.log(`\n  ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
