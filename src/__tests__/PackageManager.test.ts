import { PackageManager, PackageResult } from '../PackageManager';

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

describe('PackageManager', () => {
  let pkgManager: PackageManager;

  beforeEach(() => {
    pkgManager = new PackageManager();
  });

  describe('getPackages', () => {
    it('should get packages without tree view', async () => {
      const mockContainerOutput = `
Reading package lists...
Building dependency tree...
Reading state information...
 Package      Version
  nginx        1.21.0-1ubuntu1
  curl         7.81.0-1ubuntu1`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockContainerOutput });

      const result = await pkgManager.getPackages('nginx:latest');

      expect(result).toBeInstanceOf(Object);
      expect(result.image).toBe('nginx:latest');
      expect(result.packages).toBeInstanceOf(Array);
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.tree).toBeUndefined();
    });

    it('should get packages with tree view', async () => {
      const mockContainerOutput = `
Package      Version
  node        18.17.0
  npm         9.6.7`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockContainerOutput });

      const result = await pkgManager.getPackages('nginx:latest', { tree: true });

      expect(result).toBeInstanceOf(Object);
      expect(result.image).toBe('nginx:latest');
      expect(result.tree).toBeDefined();
      expect(result.tree?.name).toBe('root');
      expect(result.tree?.version).toBe('1.0.0');
      expect(result.tree?.dependencies).toBeInstanceOf(Array);
    });

    it('should filter packages by name', async () => {
      const mockContainerOutput = `
Package      Version
  nginx        1.21.0-1ubuntu1
  curl         7.81.0-1ubuntu1
  openssl      1.1.1f-1ubuntu2`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockContainerOutput });

      const result = await pkgManager.getPackages('nginx:latest', { filter: 'nginx' });

      expect(result.packages.every(pkg => pkg.name.includes('nginx'))).toBe(true);
      expect(result.packages.length).toBe(1);
    });

    it('should limit tree depth', async () => {
      const mockContainerOutput = `
Package      Version
  node        18.17.0
  npm         9.6.7
  libuv       1.44.0`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockContainerOutput });

      const result = await pkgManager.getPackages('nginx:latest', { tree: true, depth: 1 });

      expect(result.tree?.dependencies?.every(dep => !dep.dependencies)).toBe(true);
    });
  });

  describe('extractPackages', () => {
    it('should extract Debian packages', async () => {
      const mockContainerOutput = `
Reading package lists...
Building dependency tree...
Reading state information...
 Package      Version
  nginx        1.21.0-1ubuntu1
  curl         7.81.0-1ubuntu1
  openssl      1.1.1f-1ubuntu2`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockContainerOutput });

      const packages = await pkgManager['extractPackages']('nginx:latest');

      expect(packages.length).toBe(3);
      expect(packages[0]).toEqual({ name: 'nginx', version: '1.21.0-1ubuntu1', category: 'deb' });
      expect(packages[1]).toEqual({ name: 'curl', version: '7.81.0-1ubuntu1', category: 'apt' });
      expect(packages[2]).toEqual({ name: 'openssl', version: '1.1.1f-1ubuntu2', category: 'deb' });
    });

    it('should extract RPM packages', async () => {
      const mockContainerOutput = `
Loaded plugins: fastestmirror, ovl
Resolving Dependencies...
--> Running transaction check
---> Package nginx.x86_64 1:1.21.0-1.el8.ngx will be installed
--> Processing Dependency: libssl for package: 1:nginx-1.21.0-1.el8.ngx.x86_64
--> Running transaction check
---> Package openssl.x86_64 1:1.1.1k-1.el8 will be installed
--> Finished Dependency Resolution
nginx-1.21.0-1.el8.ngx.x86_64
openssl-1.1.1k-1.el8.x86_64`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockContainerOutput });

      const packages = await pkgManager['extractPackages']('nginx:latest');

      expect(packages.length).toBe(2);
      expect(packages[0]).toEqual({ name: 'nginx', version: '1.21.0-1.el8.ngx', category: 'rpm' });
      expect(packages[1]).toEqual({ name: 'openssl', version: '1.1.1k-1.el8', category: 'rpm' });
    });

    it('should extract Python packages', async () => {
      const mockContainerOutput = `
Package    Version
---------- -------
Flask      2.0.1
requests   2.25.1
numpy      1.21.0`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockContainerOutput });

      const packages = await pkgManager['extractPackages']('python:latest');

      expect(packages.length).toBe(3);
      expect(packages[0]).toEqual({ name: 'Flask', version: '2.0.1', category: 'pip' });
      expect(packages[1]).toEqual({ name: 'requests', version: '2.25.1', category: 'pip' });
      expect(packages[2]).toEqual({ name: 'numpy', version: '1.21.0', category: 'pip' });
    });

    it('should extract Node.js packages', async () => {
      const mockContainerOutput = `
{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.17.1",
    "body-parser": "^1.19.0"
  }
}`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockContainerOutput });

      const packages = await pkgManager['extractPackages']('node:latest');

      expect(packages.length).toBe(2);
      expect(packages[0]).toEqual({ name: 'express', version: '4.17.1', category: 'npm' });
      expect(packages[1]).toEqual({ name: 'body-parser', version: '1.19.0', category: 'npm' });
    });

    it('should extract Go packages', async () => {
      const mockContainerOutput = `
github.com/gin-gonic/gin v1.9.1
github.com/stretchr/testify v1.8.0
github.com/gorilla/mux v1.8.0`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockContainerOutput });

      const packages = await pkgManager['extractPackages']('golang:latest');

      expect(packages.length).toBe(3);
      expect(packages[0]).toEqual({ name: 'github.com/gin-gonic/gin', version: 'v1.9.1', category: 'go' });
      expect(packages[1]).toEqual({ name: 'github.com/stretchr/testify', version: 'v1.8.0', category: 'go' });
      expect(packages[2]).toEqual({ name: 'github.com/gorilla/mux', version: 'v1.8.0', category: 'go' });
    });

    it('should handle empty output gracefully', async () => {
      mockExecAsync.mockResolvedValueOnce({ stdout: '' });

      const packages = await pkgManager['extractPackages']('nginx:latest');
      expect(Array.isArray(packages)).toBe(true);
      expect(packages.length).toBe(0);
    });
  });

  describe('tryPackageSpecificCommands', () => {
    it('should try package-specific commands', async () => {
      const packages: any[] = [];

      mockExecAsync
        .mockResolvedValueOnce({ stdout: 'nginx\t1.21.0-1ubuntu1\t123456' }) // dpkg-query
        .mockResolvedValueOnce({ stdout: 'No rpm' }) // rpm (not available)
        .mockResolvedValueOnce({ stdout: 'Flask==2.0.1\nrequests==2.25.1' }) // pip list
        .mockResolvedValueOnce({ stdout: '{}'); // npm list (empty)

      await pkgManager['tryPackageSpecificCommands']('nginx:latest', packages);

      expect(packages.length).toBeGreaterThan(0);
      expect(packages.some(p => p.name === 'nginx')).toBe(true);
      expect(packages.some(p => p.name === 'Flask')).toBe(true);
      expect(packages.some(p => p.name === 'requests')).toBe(true);
    });

    it('should handle command failures gracefully', async () => {
      const packages: any[] = [];

      mockExecAsync.mockRejectedValue(new Error('command not found'));

      await pkgManager['tryPackageSpecificCommands']('nginx:latest', packages);
      
      // Should not crash even if all commands fail
      expect(Array.isArray(packages)).toBe(true);
    });
  });

  describe('parsePackageOutput', () => {
    it('should parse Debian package output', () => {
      const output = `
Package      Version
  nginx        1.21.0-1ubuntu1
  curl         7.81.0-1ubuntu1
  openssl      1.1.1f-1ubuntu2`;

      const packages = pkgManager['parsePackageOutput'](output, 'deb');

      expect(packages).toHaveLength(3);
      expect(packages[0]).toEqual({ name: 'nginx', version: '1.21.0-1ubuntu1', category: 'deb' });
      expect(packages[1]).toEqual({ name: 'curl', version: '7.81.0-1ubuntu1', category: 'deb' });
      expect(packages[2]).toEqual({ name: 'openssl', version: '1.1.1f-1ubuntu2', category: 'deb' });
    });

    it('should parse RPM package output', () => {
      const output = `
nginx-1.21.0-1.el7.ngx.x86_64	123456
curl-7.81.0-1.el8.x86_64	234567
openssl-1.1.1f-1.el8.x86_64	345678`;

      const packages = pkgManager['parsePackageOutput'](output, 'rpm');

      expect(packages).toHaveLength(3);
      expect(packages[0]).toEqual({ name: 'nginx', version: '1.21.0-1.el7.ngx', category: 'rpm' });
      expect(packages[1]).toEqual({ name: 'curl', version: '7.81.0-1.el8', category: 'rpm' });
      expect(packages[2]).toEqual({ name: 'openssl', version: '1.1.1f-1.el8', category: 'rpm' });
    });

    it('should parse pip package output', () => {
      const output = `
Flask==2.0.1
requests==2.25.1
numpy==1.21.0`;

      const packages = pkgManager['parsePackageOutput'](output, 'pip');

      expect(packages).toHaveLength(3);
      expect(packages[0]).toEqual({ name: 'Flask', version: '2.0.1', category: 'pip' });
      expect(packages[1]).toEqual({ name: 'requests', version: '2.25.1', category: 'pip' });
      expect(packages[2]).toEqual({ name: 'numpy', version: '1.21.0', category: 'pip' });
    });

    it('should parse npm package output', () => {
      const output = `{
  "dependencies": {
    "express": "^4.17.1",
    "body-parser": "^1.19.0"
  }
}`;

      const packages = pkgManager['parsePackageOutput'](output, 'npm');

      expect(packages).toHaveLength(2);
      expect(packages[0]).toEqual({ name: 'express', version: '4.17.1', category: 'npm' });
      expect(packages[1]).toEqual({ name: 'body-parser', version: '1.19.0', category: 'npm' });
    });

    it('should parse Go package output', () => {
      const output = `
github.com/gin-gonic/gin v1.9.1
github.com/stretchr/testify v1.8.0
github.com/gorilla/mux v1.8.0`;

      const packages = pkgManager['parsePackageOutput'](output, 'go');

      expect(packages).toHaveLength(3);
      expect(packages[0]).toEqual({ name: 'github.com/gin-gonic/gin', version: 'v1.9.1', category: 'go' });
      expect(packages[1]).toEqual({ name: 'github.com/stretchr/testify', version: 'v1.8.0', category: 'go' });
      expect(packages[2]).toEqual({ name: 'github.com/gorilla/mux', version: 'v1.8.0', category: 'go' });
    });
  });

  describe('buildPackageTree', () => {
    it('should build a package tree', () => {
      const packages = [
        { name: 'node', version: '18.17.0', category: 'npm' },
        { name: 'npm', version: '9.6.7', category: 'npm' },
        { name: 'libuv', version: '1.44.0', category: 'system' },
        { name: 'python', version: '3.11.0', category: 'system' }
      ];

      const tree = pkgManager['buildPackageTree'](packages);

      expect(tree.name).toBe('root');
      expect(tree.version).toBe('1.0.0');
      expect(tree.dependencies).toBeInstanceOf(Array);
      expect(tree.dependencies?.length).toBe(4);

      const nodeDep = tree.dependencies?.find(dep => dep.name === 'node');
      expect(nodeDep?.dependencies?.some(dep => dep.name === 'libuv')).toBe(true);

      const pythonDep = tree.dependencies?.find(dep => dep.name === 'python');
      expect(pythonDep?.dependencies?.some(dep => dep.name === 'libpython3')).toBe(true);
    });

    it('should handle empty packages array', () => {
      const tree = pkgManager['buildPackageTree']([]);

      expect(tree.name).toBe('root');
      expect(tree.version).toBe('1.0.0');
      expect(tree.dependencies).toBeInstanceOf(Array);
      expect(tree.dependencies?.length).toBe(0);
    });
  });

  describe('limitTreeDepth', () => {
    it('should limit tree depth', () => {
      const deepTree = {
        name: 'root',
        version: '1.0.0',
        dependencies: [
          {
            name: 'level1',
            version: '1.0.0',
            dependencies: [
              {
                name: 'level2',
                version: '1.0.0',
                dependencies: [
                  {
                    name: 'level3',
                    version: '1.0.0',
                    dependencies: [
                      {
                        name: 'level4',
                        version: '1.0.0'
                      }
                    ]
                  }
                ]
              }
            ]
          }
        ]
      };

      pkgManager['limitTreeDepth'](deepTree, 2);

      expect(deepTree.dependencies?.[0]?.dependencies?.[0]?.dependencies).toBeUndefined();
    });

    it('should handle null depth', () => {
      const tree = {
        name: 'root',
        version: '1.0.0',
        dependencies: [
          {
            name: 'level1',
            version: '1.0.0',
            dependencies: [
              {
                name: 'level2',
                version: '1.0.0'
              }
            ]
          }
        ]
      };

      pkgManager['limitTreeDepth'](tree, null as any);
      
      expect(tree.dependencies?.[0]?.dependencies).toBeDefined();
    });
  });
});