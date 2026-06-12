'use strict';

const fs = require('fs');
const path = require('path');

const SEVERITY = { error: 2, warning: 1, info: 0 };

function parseDockerfile(content) {
  const lines = content.split('\n');
  const instructions = [];
  let current = null;
  let lineNum = 0;

  for (const raw of lines) {
    lineNum++;
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    if (trimmed.endsWith('\\')) {
      const part = trimmed.slice(0, -1).trim();
      if (!current) {
        const match = part.match(/^(\S+)\s+(.*)/);
        if (match) current = { instruction: match[1].toUpperCase(), args: [match[2]], startLine: lineNum };
      } else {
        current.args.push(part);
      }
      continue;
    }

    if (current) {
      current.args.push(trimmed);
      current.args = current.args.join(' ');
      current.endLine = lineNum;
      instructions.push(current);
      current = null;
    } else {
      const match = trimmed.match(/^(\S+)\s+(.*)/);
      if (match) {
        instructions.push({
          instruction: match[1].toUpperCase(),
          args: match[2],
          startLine: lineNum,
          endLine: lineNum,
        });
      }
    }
  }
  if (current) {
    current.args = current.args.join(' ');
    current.endLine = lineNum;
    instructions.push(current);
  }
  return instructions;
}

function checkBaseImage(instruction) {
  const findings = [];
  const image = instruction.args.split(/\s+/)[0] || '';

  // Check for :latest
  if (image.includes(':latest') || (!image.includes(':') && !image.includes('@sha256:'))) {
    findings.push({
      rule: 'DL3001',
      severity: 'warning',
      message: `Base image "${image}" uses :latest tag — pin a specific version`,
      line: instruction.startLine,
    });
  }

  // Suspicious images
  const sus = ['ubuntu', 'debian', 'centos', 'fedora', 'alpine'];
  const base = image.split(':')[0].split('/').pop();
  if (sus.includes(base)) {
    findings.push({
      rule: 'DL3002',
      severity: 'info',
      message: `Using full OS image "${image}" — consider smaller images like distroless`,
      line: instruction.startLine,
    });
  }

  return findings;
}

function checkRun(instruction) {
  const findings = [];
  const args = instruction.args;

  if (args.includes('apt-get') && !args.includes('--no-install-recommends')) {
    findings.push({
      rule: 'DL3014',
      severity: 'warning',
      message: 'Use --no-install-recommends with apt-get to reduce image size',
      line: instruction.startLine,
    });
  }

  if (args.includes('apt-get') && args.includes('install') && !args.includes('-y')) {
    findings.push({
      rule: 'DL3015',
      severity: 'error',
      message: 'apt-get install without -y will fail in non-interactive build',
      line: instruction.startLine,
    });
  }

  if (args.includes('apt-get update') && !args.includes('apt-get install') && !args.includes('rm')) {
    findings.push({
      rule: 'DL3009',
      severity: 'warning',
      message: 'apt-get update without install or cleanup bloats the layer',
      line: instruction.startLine,
    });
  }

  if (args.includes('sudo')) {
    findings.push({
      rule: 'DL3004',
      severity: 'error',
      message: 'sudo not needed — RUN already executes as root unless USER is set',
      line: instruction.startLine,
    });
  }

  if (args.includes('curl') && args.includes('|') && args.includes('sh')) {
    findings.push({
      rule: 'DL4001',
      severity: 'warning',
      message: 'Piping curl to shell is a security risk — download and verify first',
      line: instruction.startLine,
    });
  }

  // Multiple RUN commands that could be combined
  if (args.includes('&&') === false && args.length > 20) {
    findings.push({
      rule: 'DL3059',
      severity: 'info',
      message: 'Consider combining consecutive RUN commands to reduce layers',
      line: instruction.startLine,
    });
  }

  return findings;
}

function checkCopyAdd(instruction) {
  const findings = [];
  const parts = instruction.args.split(/\s+/);

  if (instruction.instruction === 'ADD' && parts.length >= 2) {
    const src = parts[0];
    if (!src.startsWith('http') && !src.endsWith('.tar') && !src.endsWith('.tar.gz')) {
      findings.push({
        rule: 'DL3010',
        severity: 'info',
        message: 'Use COPY instead of ADD for simple file copies — ADD has extra behavior',
        line: instruction.startLine,
      });
    }
  }

  // Wildcard COPY .
  if (parts.some(p => p === '.' || p === '*') && instruction.instruction === 'ADD') {
    findings.push({
      rule: 'DL3011',
      severity: 'warning',
      message: 'ADD with wildcard root — may copy unwanted files, use .dockerignore',
      line: instruction.startLine,
    });
  }

  return findings;
}

function analyzeGlobal(instructions) {
  const findings = [];

  const froms = instructions.filter(i => i.instruction === 'FROM');
  if (froms.length === 0) {
    findings.push({ rule: 'DL3000', severity: 'error', message: 'No FROM instruction found', line: 0 });
  }

  // Check for USER
  const hasUser = instructions.some(i => i.instruction === 'USER');
  if (!hasUser && froms.length > 0) {
    findings.push({
      rule: 'DL3002',
      severity: 'warning',
      message: 'No USER instruction — container will run as root',
      line: 0,
    });
  }

  // Check for HEALTHCHECK
  const hasHealth = instructions.some(i => i.instruction === 'HEALTHCHECK');
  if (!hasHealth) {
    findings.push({
      rule: 'DL3003',
      severity: 'info',
      message: 'No HEALTHCHECK defined — orchestration tools won\'t know if the app is healthy',
      line: 0,
    });
  }

  // Multiple FROM without AS
  if (froms.length > 1) {
    froms.forEach((f, idx) => {
      if (idx < froms.length - 1) {
        const parts = f.args.split(/\s+/);
        const hasAlias = parts.some(p => p.toUpperCase() === 'AS');
        if (!hasAlias) {
          findings.push({
            rule: 'DL3005',
            severity: 'warning',
            message: 'Multiple FROM stages — use "AS <name>" for readability',
            line: f.startLine,
          });
        }
      }
    });
  }

  // EXPOSE with privileged port
  instructions.filter(i => i.instruction === 'EXPOSE').forEach(i => {
    const ports = i.args.split(/\s+/);
    ports.forEach(p => {
      const num = parseInt(p.split('/')[0], 10);
      if (!isNaN(num) && num < 1024) {
        findings.push({
          rule: 'DL3006',
          severity: 'info',
          message: `EXPOSE port ${num} is privileged (<1024) — non-root processes can't bind`,
          line: i.startLine,
        });
      }
    });
  });

  // ENV ordering — prefer ARG for build-time vars
  const envs = instructions.filter(i => i.instruction === 'ENV');
  const runs = instructions.filter(i => i.instruction === 'RUN');
  envs.forEach(e => {
    const varName = e.args.split('=')[0].split(/\s+/)[0];
    const usedInBuild = runs.some(r => r.args.includes(`$${varName}`));
    if (usedInBuild && !instructions.some(i => i.instruction === 'ARG' && i.args.includes(varName))) {
      findings.push({
        rule: 'DL3007',
        severity: 'info',
        message: `ENV ${varName} used only in build — consider ARG instead`,
        line: e.startLine,
      });
    }
  });

  return findings;
}

function analyze(content) {
  const instructions = parseDockerfile(content);
  let findings = [...analyzeGlobal(instructions)];

  for (const inst of instructions) {
    switch (inst.instruction) {
      case 'FROM':
        findings = findings.concat(checkBaseImage(inst));
        break;
      case 'RUN':
        findings = findings.concat(checkRun(inst));
        break;
      case 'ADD':
      case 'COPY':
        findings = findings.concat(checkCopyAdd(inst));
        break;
    }
  }

  findings.sort((a, b) => SEVERITY[b.severity] - SEVERITY[a.severity]);
  return findings;
}

function formatFindings(findings, filePath) {
  const colors = { error: '\x1b[31m', warning: '\x1b[33m', info: '\x1b[36m', reset: '\x1b[0m' };
  const icons = { error: '✗', warning: '⚠', info: 'ℹ' };

  let output = `\n  dockalyze — ${path.basename(filePath)}\n`;
  output += `  ${'─'.repeat(50)}\n\n`;

  if (findings.length === 0) {
    output += '  ✅ All clear — no issues found\n\n';
    return output;
  }

  const grouped = { error: [], warning: [], info: [] };
  findings.forEach(f => grouped[f.severity].push(f));

  for (const sev of ['error', 'warning', 'info']) {
    for (const f of grouped[sev]) {
      const c = colors[sev];
      const line = f.line ? `L${f.line}: ` : '';
      output += `  ${c}${icons[sev]} ${line}${f.message}${colors.reset}\n`;
      output += `    ${c}[${f.rule}]${colors.reset}\n\n`;
    }
  }

  const summary = Object.entries(grouped)
    .filter(([, v]) => v.length)
    .map(([k, v]) => `${v.length} ${k}${v.length > 1 ? 's' : ''}`)
    .join(', ');
  output += `  ${'─'.repeat(50)}\n`;
  output += `  ${findings.length} issue${findings.length > 1 ? 's' : ''} (${summary})\n\n`;

  return output;
}

function analyzeFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const findings = analyze(content);
  return { findings, output: formatFindings(findings, filePath) };
}

function analyzeStdin(content) {
  const findings = analyze(content);
  return { findings, output: formatFindings(findings, 'Dockerfile') };
}

module.exports = { analyze, parseDockerfile, analyzeFile, analyzeStdin, checkBaseImage, checkRun, checkCopyAdd, analyzeGlobal };
