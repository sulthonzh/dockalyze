#!/usr/bin/env node
'use strict';

const { analyzeFile, analyzeStdin } = require('../src/analyzer');
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
  dockalyze — Dockerfile best practices analyzer

  Usage:
    dockalyze <Dockerfile>
    dockalyze <directory>
    cat Dockerfile | dockalyze -
    dockalyze --help

  Checks:
    Base image tags, RUN best practices, ADD vs COPY,
    USER instruction, HEALTHCHECK, privileged ports,
    apt-get flags, sudo usage, multi-stage naming,
    ENV vs ARG, piped shell downloads, and more.

  Zero dependencies. Node >= 16.
`);
  process.exit(0);
}

function findDockerfiles(dir) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    if (e.isFile() && (e.name === 'Dockerfile' || e.name.startsWith('Dockerfile.'))) {
      results.push(path.join(dir, e.name));
    }
  }
  return results.sort();
}

if (args.length === 0) {
  const local = path.join(process.cwd(), 'Dockerfile');
  if (fs.existsSync(local)) {
    const { output } = analyzeFile(local);
    console.log(output);
  } else {
    console.error('No Dockerfile found. Run: dockalyze <path>');
    process.exit(1);
  }
} else if (args[0] === '-') {
  let data = '';
  process.stdin.setEncoding('utf-8');
  process.stdin.on('data', chunk => data += chunk);
  process.stdin.on('end', () => {
    const { findings, output } = analyzeStdin(data);
    console.log(output);
    if (findings.some(f => f.severity === 'error')) process.exit(1);
  });
} else {
  const target = path.resolve(args[0]);
  if (!fs.existsSync(target)) {
    console.error(`File not found: ${target}`);
    process.exit(1);
  }
  const stat = fs.statSync(target);
  const files = stat.isDirectory() ? findDockerfiles(target) : [target];

  if (files.length === 0) {
    console.error('No Dockerfiles found.');
    process.exit(1);
  }

  let hasError = false;
  for (const f of files) {
    const { findings, output } = analyzeFile(f);
    console.log(output);
    if (findings.some(ff => ff.severity === 'error')) hasError = true;
  }
  if (hasError) process.exit(1);
}
