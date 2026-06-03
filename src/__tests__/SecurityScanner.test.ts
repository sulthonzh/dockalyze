import { SecurityScanner, SecurityScanResult, Vulnerability } from '../scanner/SecurityScanner';

// Mock the exec function
jest.mock('child_process');
const { exec } = require('child_process');

// Mock promisify
jest.mock('util', () => ({
  ...jest.requireActual('util'),
  promisify: jest.fn(() => jest.fn())
}));

const mockExecAsync = jest.fn();

beforeEach(() => {
  mockExecAsync.mockClear();
  (require('util').promisify as jest.Mock).mockReturnValue(mockExecAsync);
});

describe('SecurityScanner', () => {
  let scanner: SecurityScanner;

  beforeEach(() => {
    scanner = new SecurityScanner();
  });

  describe('scan', () => {
    it('should scan an image for vulnerabilities', async () => {
      // Mock successful trivy scan
      mockExecAsync
        .mockResolvedValueOnce({ stdout: 'trivy version 0.34.0' }) // Check trivy version
        .mockResolvedValueOnce({ stdout: `[
          {
            "Results": [
              {
                "Target": "nginx:latest",
                "Vulnerabilities": [
                  {
                    "VulnerabilityID": "CVE-2021-3711",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1f",
                    "Severity": "HIGH",
                    "Description": "Buffer overflow in certificate verification",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2021-3711"
                  }
                ]
              }
            ]
          }
        ]` });

      const result = await scanner.scan('nginx:latest');

      expect(result).toBeInstanceOf(Object);
      expect(result.image).toBe('nginx:latest');
      expect(result.vulnerabilities).toBeInstanceOf(Object);
      expect(result.vulnerabilities.high).toHaveLength(1);
      expect(result.vulnerabilities.high[0].id).toBe('CVE-2021-3711');
      expect(result.vulnerabilities.high[0].package).toBe('openssl');
      expect(result.vulnerabilities.high[0].severity).toBe('high');
      expect(result.summary.high).toBe(1);
      expect(result.summary.total).toBe(1);
    });

    it('should filter by severity', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: 'trivy version 0.34.0' })
        .mockResolvedValueOnce({ stdout: `[
          {
            "Results": [
              {
                "Target": "nginx:latest",
                "Vulnerabilities": [
                  {
                    "VulnerabilityID": "CVE-2021-3711",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1f",
                    "Severity": "HIGH",
                    "Description": "Buffer overflow"
                  }
                ]
              }
            ]
          }
        ]` });

      const result = await scanner.scan('nginx:latest', { severity: 'high,critical' });

      expect(result.vulnerabilities.high).toHaveLength(1);
      expect(result.vulnerabilities.medium).toHaveLength(0);
      expect(result.vulnerabilities.low).toHaveLength(0);
      expect(result.vulnerabilities.critical).toHaveLength(0);
    });

    it('should exclude specified packages', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: 'trivy version 0.34.0' })
        .mockResolvedValueOnce({ stdout: `[
          {
            "Results": [
              {
                "Target": "nginx:latest",
                "Vulnerabilities": [
                  {
                    "VulnerabilityID": "CVE-2021-3711",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1f",
                    "Severity": "HIGH",
                    "Description": "Buffer overflow"
                  }
                ]
              }
            ]
          }
        ]` });

      const result = await scanner.scan('nginx:latest', { exclude: 'openssl' });

      expect(result.vulnerabilities.high).toHaveLength(0);
    });

    it('should fallback to basic scanning when trivy fails', async () => {
      mockExecAsync
        .mockRejectedValueOnce(new Error('command not found')) // trivy not available
        .mockResolvedValueOnce({ stdout: '' }); // No package info

      const result = await scanner.scan('nginx:latest');

      expect(result).toBeInstanceOf(Object);
      expect(result.image).toBe('nginx:latest');
      expect(result.vulnerabilities).toBeInstanceOf(Object);
    });
  });

  describe('scanWithTrivy', () => {
    it('should scan with trivy when available', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: 'trivy version 0.34.0' })
        .mockResolvedValueOnce({ stdout: `[
          {
            "Results": [
              {
                "Target": "nginx:latest",
                "Vulnerabilities": [
                  {
                    "VulnerabilityID": "CVE-2021-3711",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1f",
                    "Severity": "HIGH",
                    "Description": "Buffer overflow"
                  }
                ]
              }
            ]
          }
        ]` });

      const vulnerabilities = {
        critical: [],
        high: [],
        medium: [],
        low: []
      };

      await scanner['scanWithTrivy']('nginx:latest', vulnerabilities, ['high', 'medium', 'low', 'critical'], []);

      expect(vulnerabilities.high).toHaveLength(1);
      expect(vulnerabilities.high[0].id).toBe('CVE-2021-3711');
      expect(vulnerabilities.high[0].package).toBe('openssl');
    });

    it('should handle trivy not available', async () => {
      mockExecAsync.mockRejectedValueOnce(new Error('command not found'));

      const vulnerabilities = {
        critical: [],
        high: [],
        medium: [],
        low: []
      };

      await scanner['scanWithTrivy']('nginx:latest', vulnerabilities, ['high', 'medium', 'low', 'critical'], []);

      expect(vulnerabilities.high).toHaveLength(0);
    });
  });

  describe('scanWithGrype', () => {
    it('should scan with grype when available', async () => {
      mockExecAsync
        .mockResolvedValueOnce({ stdout: 'grype version 0.50.0' })
        .mockResolvedValueOnce({ stdout: `{
          "matches": [
            {
              "artifact": {
                "name": "openssl",
                "version": "1.1.1f"
              },
              "vulnerability": {
                "id": "CVE-2021-3711",
                "severity": "High",
                "description": "Buffer overflow in certificate verification",
                "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3711"],
                "fix": {
                  "versions": ["1.1.1g"]
                }
              }
            }
          ]
        }` });

      const vulnerabilities = {
        critical: [],
        high: [],
        medium: [],
        low: []
      };

      await scanner['scanWithGrype']('nginx:latest', vulnerabilities, ['high', 'medium', 'low', 'critical'], []);

      expect(vulnerabilities.high).toHaveLength(1);
      expect(vulnerabilities.high[0].id).toBe('CVE-2021-3711');
      expect(vulnerabilities.high[0].package).toBe('openssl');
    });

    it('should handle grype not available', async () => {
      mockExecAsync.mockRejectedValueOnce(new Error('command not found'));

      const vulnerabilities = {
        critical: [],
        high: [],
        medium: [],
        low: []
      };

      await scanner['scanWithGrype']('nginx:latest', vulnerabilities, ['high', 'medium', 'low', 'critical'], []);

      expect(vulnerabilities.high).toHaveLength(0);
    });
  });

  describe('fallbackVulnerabilityScan', () => {
    it('should perform basic vulnerability detection', async () => {
      mockExecResolvedValueOnce({ stdout: '' }); // No package info

      const vulnerabilities = {
        critical: [],
        high: [],
        medium: [],
        low: []
      };

      await scanner['fallbackVulnerabilityScan']('nginx:latest', vulnerabilities, ['high', 'medium', 'low', 'critical'], []);

      expect(Array.isArray(vulnerabilities)).toBe(true);
    });

    it('should detect known vulnerable packages', async () => {
      const mockPackageInfo = [
        { name: 'openssl', version: '1.1.1f' },
        { name: 'nginx', version: '1.18.0' }
      ];

      jest.spyOn(scanner, 'extractPackageInfo').mockResolvedValue(mockPackageInfo);

      const vulnerabilities = {
        critical: [],
        high: [],
        medium: [],
        low: []
      };

      await scanner['fallbackVulnerabilityScan']('nginx:latest', vulnerabilities, ['high', 'medium', 'low', 'critical'], []);

      expect(vulnerabilities.high.length).toBeGreaterThan(0);
    });

    it('should check for outdated packages', async () => {
      jest.spyOn(scanner, 'extractPackageInfo').mockResolvedValue([
        { name: 'node', version: '14.17.0' }
      ]);

      jest.spyOn(scanner, 'checkOutdatedPackages').mockResolvedValue([
        { name: 'node', version: '14.17.0', latestVersion: '18.17.0' }
      ]);

      const vulnerabilities = {
        critical: [],
        high: [],
        medium: [],
        low: []
      };

      await scanner['fallbackVulnerabilityScan']('nginx:latest', vulnerabilities, ['high', 'medium', 'low', 'critical'], []);

      expect(vulnerabilities.medium.length).toBeGreaterThan(0);
    });
  });

  describe('checkKnownVulnerabilities', () => {
    it('should detect OpenSSL vulnerabilities', () => {
      const pkg = { name: 'openssl', version: '1.1.1f' };
      const vulnerabilities = scanner['checkKnownVulnerabilities'](pkg);

      expect(vulnerabilities).toHaveLength(2); // 2 known vulnerabilities for OpenSSL
      expect(vulnerabilities[0].id).toBe('CVE-2020-1971');
      expect(vulnerabilities[0].package).toBe('openssl');
      expect(vulnerabilities[0].severity).toBe('critical');
      expect(vulnerabilities[0].description).toContain('memory corruption');
    });

    it('should detect curl vulnerabilities', () => {
      const pkg = { name: 'curl', version: '7.68.0' };
      const vulnerabilities = scanner['checkKnownVulnerabilities'](pkg);

      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].id).toBe('CVE-2020-8285');
      expect(vulnerabilities[0].package).toBe('curl');
      expect(vulnerabilities[0].severity).toBe('high');
    });

    it('should return empty array for unknown packages', () => {
      const pkg = { name: 'unknown-package', version: '1.0.0' };
      const vulnerabilities = scanner['checkKnownVulnerabilities'](pkg);

      expect(vulnerabilities).toHaveLength(0);
    });
  });

  describe('checkOutdatedPackages', () => {
    it('should detect outdated packages', async () => {
      const outdated = await scanner['checkOutdatedPackages']('nginx:latest');

      expect(Array.isArray(outdated)).toBe(true);
      expect(outdated.length).toBeGreaterThan(0);
      
      const nodePackage = outdated.find(p => p.name === 'node');
      expect(nodePackage).toBeDefined();
      expect(nodePackage.version).toBe('1.0.0');
      expect(nodePackage.latestVersion).toBe('18.17.0');
    });
  });

  describe('extractPackageInfo', () => {
    it('should extract package information from container output', async () => {
      const mockOutput = `
Reading package lists...
Building dependency tree...
Reading state information...
 Package      Version
  nginx        1.21.0-1ubuntu1
  curl         7.81.0-1ubuntu1
  openssl      1.1.1f-1ubuntu2`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockOutput });

      const packages = await scanner['extractPackageInfo']('nginx:latest');

      expect(packages.length).toBeGreaterThan(0);
      expect(packages.some(p => p.name === 'nginx' && p.version === '1.21.0-1ubuntu1')).toBe(true);
      expect(packages.some(p => p.name === 'curl' && p.version === '7.81.0-1ubuntu1')).toBe(true);
    });

    it('should handle empty output', async () => {
      mockExecAsync.mockResolvedValueOnce({ stdout: '' });

      const packages = await scanner['extractPackageInfo']('nginx:latest');
      expect(Array.isArray(packages)).toBe(true);
    });
  });

  describe('package extraction methods', () => {
    it('should extract Debian packages correctly', () => {
      const output = `
Package      Version
  nginx        1.21.0-1ubuntu1
  curl         7.81.0-1ubuntu1
  openssl      1.1.1f-1ubuntu2`;

      const packages = scanner['extractDebPackages'](output);
      
      expect(packages).toHaveLength(3);
      expect(packages[0]).toEqual({ name: 'nginx', version: '1.21.0-1ubuntu1' });
      expect(packages[1]).toEqual({ name: 'curl', version: '7.81.0-1ubuntu1' });
      expect(packages[2]).toEqual({ name: 'openssl', version: '1.1.1f-1ubuntu2' });
    });

    it('should extract RPM packages correctly', () => {
      const output = `
nginx-1.21.0-1.el7.ngx.x86_64	123456
curl-7.81.0-1.el8.x86_64	234567
openssl-1.1.1f-1.el8.x86_64	345678`;

      const packages = scanner['extractRpmPackages'](output);
      
      expect(packages).toHaveLength(3);
      expect(packages[0]).toEqual({ name: 'nginx', version: '1.21.0-1.el7.ngx' });
      expect(packages[1]).toEqual({ name: 'curl', version: '7.81.0-1.el8' });
      expect(packages[2]).toEqual({ name: 'openssl', version: '1.1.1f-1.el8' });
    });

    it('should extract Python packages correctly', () => {
      const output = `
Flask==2.0.1
requests==2.25.1
numpy==1.21.0
pandas==1.3.0`;

      const packages = scanner['extractPipPackages'](output);
      
      expect(packages).toHaveLength(4);
      expect(packages[0]).toEqual({ name: 'Flask', version: '2.0.1' });
      expect(packages[1]).toEqual({ name: 'requests', version: '2.25.1' });
      expect(packages[2]).toEqual({ name: 'numpy', version: '1.21.0' });
      expect(packages[3]).toEqual({ name: 'pandas', version: '1.3.0' });
    });
  });
});