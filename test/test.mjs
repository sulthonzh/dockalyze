import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

const { DockerAnalyzer } = await import('../dist/analyzer/DockerAnalyzer.js');
const { SecurityScanner } = await import('../dist/scanner/SecurityScanner.js');
const { PackageManager } = await import('../dist/PackageManager.js');
const { SizeAnalyzer } = await import('../dist/analyzer/SizeAnalyzer.js');
const { LayerAnalyzer } = await import('../dist/analyzer/LayerAnalyzer.js');

// ============================================================
// DockerAnalyzer — pure parsing functions
// ============================================================
describe('DockerAnalyzer', () => {
  const analyzer = new DockerAnalyzer();

  describe('parseSize', () => {
    it('parses GB', () => {
      assert.equal(analyzer.parseSize('1.5GB'), 1.5 * 1024 * 1024 * 1024);
    });

    it('parses MB', () => {
      assert.equal(analyzer.parseSize('256MB'), 256 * 1024 * 1024);
    });

    it('parses KB', () => {
      assert.equal(analyzer.parseSize('512KB'), 512 * 1024);
    });

    it('parses bytes suffix', () => {
      assert.equal(analyzer.parseSize('1024B'), 1024);
    });

    it('parses bare number as bytes', () => {
      assert.equal(analyzer.parseSize('2048'), 2048);
    });

    it('returns 0 for empty string', () => {
      assert.equal(analyzer.parseSize(''), 0);
    });

    it('returns 0 for "0"', () => {
      assert.equal(analyzer.parseSize('0'), 0);
    });

    it('handles whitespace', () => {
      assert.equal(analyzer.parseSize('  10MB  '), 10 * 1024 * 1024);
    });
  });

  describe('parseCreatedBy', () => {
    it('extracts single CMD', () => {
      const result = analyzer.parseCreatedBy(' /bin/sh -c #(nop)  CMD ["nginx"]');
      assert.equal(result.length, 1);
      assert.ok(result[0].includes('CMD'));
    });

    it('extracts RUN command', () => {
      const result = analyzer.parseCreatedBy(' /bin/sh -c apt-get update && apt-get install -y curl');
      assert.deepEqual(result, ['apt-get update && apt-get install -y curl']);
    });

    it('returns empty for nop prefix only', () => {
      const result = analyzer.parseCreatedBy('/bin/sh -c #(nop)');
      assert.deepEqual(result, []);
    });

    it('truncates long commands', () => {
      const longCmd = 'a'.repeat(60);
      const result = analyzer.parseCreatedBy(` /bin/sh -c ${longCmd}`);
      assert.equal(result[0].length, 50); // 47 + '...'
      assert.ok(result[0].endsWith('...'));
    });
  });

  describe('parseDpkgOutput', () => {
    it('parses tab-separated name and version', () => {
      const output = 'nginx\t1.21.0-1ubuntu1\nlibc6\t2.35-0ubuntu3';
      const pkgs = analyzer.parseDpkgOutput(output);
      assert.equal(pkgs.length, 2);
      assert.equal(pkgs[0].name, 'nginx');
      assert.equal(pkgs[0].version, '1.21.0-1ubuntu1');
      assert.equal(pkgs[0].category, 'deb');
      assert.equal(pkgs[1].name, 'libc6');
    });

    it('skips empty lines', () => {
      const output = 'nginx\t1.0\n\n\n';
      const pkgs = analyzer.parseDpkgOutput(output);
      assert.equal(pkgs.length, 1);
    });

    it('handles single line with no tab', () => {
      const output = 'nginx';
      const pkgs = analyzer.parseDpkgOutput(output);
      assert.equal(pkgs.length, 1);
      assert.equal(pkgs[0].name, 'nginx');
      assert.equal(pkgs[0].version, 'unknown');
    });
  });

  describe('parseRpmOutput', () => {
    it('parses rpm tab output', () => {
      const output = 'nginx\t1.21.0\t123456\nlibc6\t2.35\t234567';
      const pkgs = analyzer.parseRpmOutput(output);
      assert.equal(pkgs.length, 2);
      assert.equal(pkgs[0].name, 'nginx');
      assert.equal(pkgs[0].version, '1.21.0');
      assert.equal(pkgs[0].size, 123456);
      assert.equal(pkgs[0].category, 'rpm');
    });
  });

  describe('parsePipOutput', () => {
    it('parses pip freeze format', () => {
      const output = 'Flask==2.0.1\nrequests==2.25.1\nnumpy==1.21.0';
      const pkgs = analyzer.parsePipOutput(output);
      assert.equal(pkgs.length, 3);
      assert.equal(pkgs[0].name, 'Flask');
      assert.equal(pkgs[0].version, '2.0.1');
      assert.equal(pkgs[0].category, 'pip');
    });

    it('handles line without ==', () => {
      const output = 'somepackage';
      const pkgs = analyzer.parsePipOutput(output);
      assert.equal(pkgs.length, 1);
      assert.equal(pkgs[0].version, 'unknown');
    });
  });

  describe('parseNpmOutput', () => {
    it('parses npm list json', () => {
      const output = JSON.stringify({
        dependencies: {
          express: { version: '4.17.1' },
          lodash: { version: '4.17.21' }
        }
      });
      const pkgs = analyzer.parseNpmOutput(output);
      assert.equal(pkgs.length, 2);
      assert.equal(pkgs[0].name, 'express');
      assert.equal(pkgs[0].version, '4.17.1');
      assert.equal(pkgs[0].category, 'npm');
    });

    it('returns empty for invalid JSON', () => {
      const pkgs = analyzer.parseNpmOutput('not json');
      assert.deepEqual(pkgs, []);
    });

    it('returns empty when no dependencies', () => {
      const pkgs = analyzer.parseNpmOutput('{"dependencies": {}}');
      assert.deepEqual(pkgs, []);
    });
  });
});

// ============================================================
// SecurityScanner — vulnerability checking
// ============================================================
describe('SecurityScanner', () => {
  const scanner = new SecurityScanner();

  describe('checkKnownVulnerabilities', () => {
    it('detects openssl vulnerabilities', () => {
      const vulns = scanner.checkKnownVulnerabilities({ name: 'openssl', version: '1.0.1' });
      assert.ok(vulns.length > 0);
      assert.ok(vulns.some(v => v.severity === 'critical'));
      assert.ok(vulns.some(v => v.cve && v.cve.startsWith('CVE-')));
    });

    it('detects sudo vulnerabilities', () => {
      const vulns = scanner.checkKnownVulnerabilities({ name: 'sudo', version: '1.8.0' });
      assert.ok(vulns.length > 0);
      assert.equal(vulns[0].severity, 'critical');
    });

    it('detects curl vulnerabilities', () => {
      const vulns = scanner.checkKnownVulnerabilities({ name: 'curl', version: '7.80.0' });
      assert.ok(vulns.length > 0);
      assert.ok(vulns[0].fixedIn);
    });

    it('detects bash vulnerabilities', () => {
      const vulns = scanner.checkKnownVulnerabilities({ name: 'bash', version: '4.2' });
      assert.ok(vulns.length > 0);
    });

    it('returns empty for unknown package', () => {
      const vulns = scanner.checkKnownVulnerabilities({ name: 'mypackage', version: '1.0.0' });
      assert.deepEqual(vulns, []);
    });

    it('is case insensitive', () => {
      const vulns = scanner.checkKnownVulnerabilities({ name: 'OpenSSL', version: '1.0.0' });
      assert.ok(vulns.length > 0);
    });
  });

  describe('extractDebPackages', () => {
    it('extracts from text with package patterns', () => {
      const output = 'nginx 1.21.0\nopenssl 1.1.1k';
      const pkgs = scanner.extractDebPackages(output);
      assert.ok(pkgs.length > 0);
    });
  });

  describe('extractPipPackages', () => {
    it('extracts pip freeze style', () => {
      const output = 'Flask==2.0.1\nrequests==2.25.1';
      const pkgs = scanner.extractPipPackages(output);
      assert.ok(pkgs.length >= 2);
      assert.ok(pkgs.some(p => p.name === 'Flask'));
    });
  });

  describe('extractNpmPackages', () => {
    it('extracts from JSON-like strings', () => {
      const output = '"express": "4.17.1"\n"lodash": "4.17.21"';
      const pkgs = scanner.extractNpmPackages(output);
      assert.ok(pkgs.length >= 2);
    });
  });
});

// ============================================================
// PackageManager — tree + parsing
// ============================================================
describe('PackageManager', () => {
  const pm = new PackageManager();

  describe('buildPackageTree', () => {
    it('builds tree from package list', () => {
      const pkgs = [
        { name: 'express', version: '4.17.1', category: 'npm' },
        { name: 'nginx', version: '1.21.0', category: 'deb' }
      ];
      const tree = pm.buildPackageTree(pkgs);
      assert.equal(tree.name, 'root');
      assert.ok(tree.dependencies);
      assert.equal(tree.dependencies.length, 2);
    });

    it('adds node dependencies for node packages', () => {
      const pkgs = [{ name: 'node', version: '18.0.0', category: 'system' }];
      const tree = pm.buildPackageTree(pkgs);
      const nodePkg = tree.dependencies.find(d => d.name === 'node');
      assert.ok(nodePkg.dependencies);
      assert.ok(nodePkg.dependencies.some(d => d.name === 'libuv'));
    });

    it('adds python dependencies for python packages', () => {
      const pkgs = [{ name: 'python', version: '3.11.0', category: 'system' }];
      const tree = pm.buildPackageTree(pkgs);
      const pyPkg = tree.dependencies.find(d => d.name === 'python');
      assert.ok(pyPkg.dependencies);
      assert.ok(pyPkg.dependencies.some(d => d.name === 'libpython3'));
    });

    it('handles empty package list', () => {
      const tree = pm.buildPackageTree([]);
      assert.equal(tree.name, 'root');
      assert.deepEqual(tree.dependencies, []);
    });
  });

  describe('limitTreeDepth', () => {
    it('trims dependencies at depth limit', () => {
      const tree = {
        name: 'root', version: '1.0',
        dependencies: [
          { name: 'a', version: '1.0', dependencies: [{ name: 'b', version: '2.0' }] }
        ]
      };
      pm.limitTreeDepth(tree, 1);
      assert.equal(tree.dependencies[0].dependencies, undefined);
    });

    it('keeps dependencies when depth > 1', () => {
      const tree = {
        name: 'root', version: '1.0',
        dependencies: [
          { name: 'a', version: '1.0', dependencies: [{ name: 'b', version: '2.0' }] }
        ]
      };
      pm.limitTreeDepth(tree, 2);
      assert.ok(tree.dependencies[0].dependencies);
    });
  });

  describe('parsePackageOutput', () => {
    it('parses pip format via extractPythonPackages', () => {
      const output = 'Flask 2.0.1\nrequests 2.25.1';
      const pkgs = pm.extractPythonPackages(output);
      assert.ok(pkgs.length >= 2);
      assert.equal(pkgs[0].category, 'pip');
    });

    it('parses deb format', () => {
      const output = 'nginx\t1.21.0-1\nlibc6\t2.35';
      const pkgs = pm.parsePackageOutput(output, 'deb');
      assert.ok(pkgs.length >= 1);
    });

    it('parses npm json format', () => {
      const output = JSON.stringify({ dependencies: { express: { version: '4.17.1' } } });
      const pkgs = pm.parsePackageOutput(output, 'npm');
      assert.equal(pkgs.length, 1);
      assert.equal(pkgs[0].name, 'express');
    });
  });

  describe('extractRustPackages', () => {
    it('returns empty (not implemented)', () => {
      const pkgs = pm.extractRustPackages('anything');
      assert.deepEqual(pkgs, []);
    });
  });

  describe('extractJavaPackages', () => {
    it('returns empty (not implemented)', () => {
      const pkgs = pm.extractJavaPackages('anything');
      assert.deepEqual(pkgs, []);
    });
  });
});

// ============================================================
// SizeAnalyzer — size parsing + distribution
// ============================================================
describe('SizeAnalyzer', () => {
  const sa = new SizeAnalyzer();

  describe('parseHumanReadableSize', () => {
    it('parses GB', () => {
      assert.equal(sa.parseHumanReadableSize('2.5GB'), 2.5 * 1024 * 1024 * 1024);
    });

    it('parses MB', () => {
      assert.equal(sa.parseHumanReadableSize('100MB'), 100 * 1024 * 1024);
    });

    it('parses KB', () => {
      assert.equal(sa.parseHumanReadableSize('512KB'), 512 * 1024);
    });

    it('parses bytes suffix', () => {
      assert.equal(sa.parseHumanReadableSize('2048B'), 2048);
    });

    it('parses bare number', () => {
      assert.equal(sa.parseHumanReadableSize('4096'), 4096);
    });

    it('returns 0 for empty or zero', () => {
      assert.equal(sa.parseHumanReadableSize(''), 0);
      assert.equal(sa.parseHumanReadableSize('0'), 0);
    });
  });

  describe('analyzeSizeDistribution', () => {
    it('categorizes files by size', () => {
      const files = [
        { path: '/a', size: 500 },           // < 1KB
        { path: '/b', size: 50 * 1024 },     // 1KB - 1MB
        { path: '/c', size: 50 * 1024 * 1024 }, // 1MB - 100MB
        { path: '/d', size: 500 * 1024 * 1024 }, // > 100MB
      ];
      const dist = sa.analyzeSizeDistribution(files);
      assert.equal(dist.small, 1);
      assert.equal(dist.medium, 1);
      assert.equal(dist.large, 1);
      assert.equal(dist.huge, 1);
    });

    it('handles empty file list', () => {
      const dist = sa.analyzeSizeDistribution([]);
      assert.equal(dist.small + dist.medium + dist.large + dist.huge, 0);
    });
  });

  describe('getLargestFiles', () => {
    it('returns top N files sorted by size desc', () => {
      const files = [
        { path: '/small', size: 100 },
        { path: '/big', size: 10000 },
        { path: '/medium', size: 1000 },
      ];
      const largest = sa.getLargestFiles(files);
      assert.ok(largest.length <= 10);
      if (largest.length >= 2) {
        assert.ok(largest[0].size >= largest[1].size);
      }
    });
  });

  describe('parseCreatedBy', () => {
    it('extracts commands from docker history', () => {
      const result = sa.parseCreatedBy(' /bin/sh -c apt-get update');
      assert.deepEqual(result, ['apt-get update']);
    });

    it('returns empty for nop only', () => {
      const result = sa.parseCreatedBy('/bin/sh -c #(nop)');
      assert.deepEqual(result, []);
    });
  });
});

// ============================================================
// LayerAnalyzer — layer analysis helpers
// ============================================================
describe('LayerAnalyzer', () => {
  const la = new LayerAnalyzer();

  describe('analyzeLayerDistribution', () => {
    it('categorizes layers by size', () => {
      const layers = [
        { id: 'a', size: 500 * 1024, commands: [] },       // < 1MB → small
        { id: 'b', size: 5 * 1024 * 1024, commands: [] },  // 1-10MB → medium
        { id: 'c', size: 50 * 1024 * 1024, commands: [] }, // 10-100MB → large
        { id: 'd', size: 500 * 1024 * 1024, commands: [] }, // > 100MB → huge
      ];
      const dist = la.analyzeLayerDistribution(layers);
      assert.equal(dist.small, 1);
      assert.equal(dist.medium, 1);
      assert.equal(dist.large, 1);
      assert.equal(dist.huge, 1);
    });
  });

  describe('analyzeOptimization', () => {
    it('flags large layers', () => {
      const layers = [
        { id: 'abc123456789', size: 200 * 1024 * 1024, commands: ['RUN something'] }
      ];
      const result = la.analyzeOptimization(layers);
      assert.ok(result.opportunities.length > 0);
      assert.ok(result.recommendations.length > 0);
    });

    it('flags layers with many commands', () => {
      const layers = [
        { id: 'xyz', size: 1024, commands: ['RUN a', 'RUN b', 'RUN c', 'RUN d'] }
      ];
      const result = la.analyzeOptimization(layers);
      assert.ok(result.opportunities.some(o => o.issue.includes('commands')));
    });

    it('returns empty for clean layers', () => {
      const layers = [
        { id: 'ok', size: 1024, commands: ['COPY . .'] }
      ];
      const result = la.analyzeOptimization(layers);
      assert.equal(result.opportunities.length, 0);
    });
  });

  describe('findConsecutiveCopyLayers', () => {
    it('finds COPY/ADD layers', () => {
      const layers = [
        { id: 'a', size: 100, commands: ['COPY file /app/'] },
        { id: 'b', size: 100, commands: ['RUN build'] },
        { id: 'c', size: 100, commands: ['ADD archive /opt/'] }
      ];
      const copyLayers = la.findConsecutiveCopyLayers(layers);
      assert.equal(copyLayers.length, 2);
    });

    it('returns empty when no copy layers', () => {
      const layers = [
        { id: 'a', size: 100, commands: ['RUN build'] }
      ];
      const copyLayers = la.findConsecutiveCopyLayers(layers);
      assert.equal(copyLayers.length, 0);
    });
  });

  describe('parseCreatedDate', () => {
    it('parses valid date string', () => {
      const result = la.parseCreatedDate('2024-01-15 12:00:00 +0000 UTC');
      assert.ok(result.startsWith('2024-01-15'));
    });

    it('returns current date for empty string', () => {
      const result = la.parseCreatedDate('');
      assert.ok(result); // just a valid ISO date
    });

    it('returns current date for zero date', () => {
      const result = la.parseCreatedDate('0001-01-01 00:00:00 +0000 UTC');
      assert.ok(result);
    });
  });

  describe('formatSize', () => {
    it('formats bytes', () => {
      assert.equal(la.formatSize(0), '0 B');
    });

    it('formats GB', () => {
      const result = la.formatSize(1.5 * 1024 * 1024 * 1024);
      assert.ok(result.includes('GB'));
    });

    it('formats MB', () => {
      const result = la.formatSize(50 * 1024 * 1024);
      assert.ok(result.includes('MB'));
    });

    it('formats KB', () => {
      const result = la.formatSize(10 * 1024);
      assert.ok(result.includes('KB'));
    });
  });
});
