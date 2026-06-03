import { DockerAnalyzer, ImageAnalysis, LayerInfo, PackageInfo } from '../analyzer/DockerAnalyzer';

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

describe('DockerAnalyzer', () => {
  let analyzer: DockerAnalyzer;

  beforeEach(() => {
    analyzer = new DockerAnalyzer();
  });

  describe('analyze', () => {
    it('should analyze a Docker image successfully', async () => {
      // Mock successful exec calls
      mockExecAsync
        .mockResolvedValueOnce({ stdout: '142.8MB' }) // getImageSize
        .mockResolvedValueOnce({ stdout: '{"Config": {"Labels": {}, "Env": []}, "Created": "2024-01-01T00:00:00Z", "Architecture": "amd64", "Os": "linux"}' }) // inspectImage
        .mockResolvedValueOnce({ stdout: 'sha256:123\t1.2MB\t/bin/sh -c #(nop)  CMD [\"nginx\"]\nsha256:456\t2.3MB\t/bin/sh -c #(nop) COPY file:123 /usr/share/nginx/html/\n' }) // getImageHistory
        .mockResolvedValueOnce({ stdout: 'nginx\t1.21.0\n' }); // extractPackages

      const result = await analyzer.analyze('nginx:latest');

      expect(result).toBeInstanceOf(Object);
      expect(result.image).toBe('nginx:latest');
      expect(result.size).toBeGreaterThan(0);
      expect(result.layers).toBeInstanceOf(Array);
      expect(result.packages).toBeInstanceOf(Array);
      expect(result.labels).toBeInstanceOf(Object);
      expect(result.environment).toBeInstanceOf(Object);
      expect(result.created).toBeDefined();
      expect(result.architecture).toBe('amd64');
      expect(result.os).toBe('linux');
    });

    it('should handle errors in image analysis', async () => {
      mockExecAsync.mockRejectedValue(new Error('Docker command failed'));

      await expect(analyzer.analyze('nginx:latest')).rejects.toThrow('Failed to get image size');
    });
  });

  describe('getImageSize', () => {
    it('should parse GB sizes correctly', async () => {
      mockExecAsync.mockResolvedValueOnce({ stdout: '1.2GB' });

      const result = await analyzer.getImageSize('nginx:latest');
      expect(result.size).toBe(1.2 * 1024 * 1024 * 1024);
    });

    it('should parse MB sizes correctly', async () => {
      mockExecAsync.mockResolvedValueOnce({ stdout: '142.8MB' });

      const result = await analyzer.getImageSize('nginx:latest');
      expect(result.size).toBe(142.8 * 1024 * 1024);
    });

    it('should parse KB sizes correctly', async () => {
      mockExecAsync.mockResolvedValueOnce({ stdout: '512KB' });

      const result = await analyzer.getImageSize('nginx:latest');
      expect(result.size).toBe(512 * 1024);
    });

    it('should parse byte sizes correctly', async () => {
      mockExecAsync.mockResolvedValueOnce({ stdout: '1024' });

      const result = await analyzer.getImageSize('nginx:latest');
      expect(result.size).toBe(1024);
    });
  });

  describe('inspectImage', () => {
    it('should parse image inspect output correctly', async () => {
      const mockInspectData = {
        Config: {
          Labels: {
            'maintainer': 'NGINX Docker Maintainers <docker-maintainer@nginx.com>',
            'version': '1.21.0'
          },
          Env: [
            'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'NGINX_VERSION=1.21.0'
          ]
        },
        Created: '2024-01-01T00:00:00Z',
        Architecture: 'amd64',
        Os: 'linux'
      };

      mockExecAsync.mockResolvedValueOnce({
        stdout: JSON.stringify([mockInspectData])
      });

      const result = await analyzer.inspectImage('nginx:latest');
      
      expect(result.Config.Labels['maintainer']).toBe('NGINIX Docker Maintainers <docker-maintainer@nginx.com>');
      expect(result.Config.Env).toContain('NGINX_VERSION=1.21.0');
      expect(result.Architecture).toBe('amd64');
      expect(result.Os).toBe('linux');
    });
  });

  describe('getImageHistory', () => {
    it('should parse image history correctly', async () => {
      const mockHistoryOutput = `sha256:123\t1.2MB\t/bin/sh -c #(nop)  CMD ["nginx"]
sha256:456\t2.3MB\t/bin/sh -c #(nop) COPY file:123 /usr/share/nginx/html/
sha256:789\t3.4MB\t/bin/sh -c #(nop) ADD file:abc /etc/nginx/`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockHistoryOutput });

      const result = await analyzer.getImageHistory('nginx:latest');

      expect(result).toBeInstanceOf(Array);
      expect(result.length).toBe(3);
      expect(result[0].id).toBe('sha256:123');
      expect(result[0].size).toBe(1.2 * 1024 * 1024);
      expect(result[0].commands).toEqual(['CMD ["nginx"]']);
      expect(result[1].diffSize).toBe(1.2 * 1024 * 1024);
      expect(result[2].commands).toEqual(['ADD file:abc /etc/nginx/']);
    });

    it('should handle empty history output', async () => {
      mockExecAsync.mockResolvedValueOnce({ stdout: '' });

      const result = await analyzer.getImageHistory('nginx:latest');
      expect(result).toBeInstanceOf(Array);
      expect(result.length).toBe(0);
    });
  });

  describe('extractPackages', () => {
    it('should extract Debian packages successfully', async () => {
      const mockContainerOutput = `Reading package lists...
Building dependency tree...
Reading state information...
 Package      Version
  nginx        1.21.0-1ubuntu1
  libc6        2.35-0ubuntu3`;

      mockExecAsync.mockResolvedValueOnce({ stdout: mockContainerOutput });

      const packages = await analyzer.extractPackages('nginx:latest');

      expect(packages.length).toBeGreaterThan(0);
      expect(packages.some(p => p.name === 'nginx' && p.version === '1.21.0-1ubuntu1')).toBe(true);
      expect(packages.some(p => p.name === 'libc6' && p.version === '2.35-0ubuntu3')).toBe(true);
    });

    it('should handle missing package managers gracefully', async () => {
      mockExecAsync.mockResolvedValueOnce({ stdout: '' }); // Empty output for all commands

      const packages = await analyzer.extractPackages('nginx:latest');
      // Should return empty array or minimal packages
      expect(Array.isArray(packages)).toBe(true);
    });
  });

  describe('parseCreatedBy', () => {
    it('should parse complex commands correctly', () => {
      const createdBy = '/bin/sh -c #(nop)  CMD ["nginx"]';
      const commands = analyzer['parseCreatedBy'](createdBy);
      
      expect(commands).toEqual(['CMD ["nginx"]']);
    });

    it('should handle multiple commands', () => {
      const createdBy = '/bin/sh -c #(nop)  COPY file:abc /etc/nginx/ /bin/sh -c #(nop)  RUN apt-get update';
      const commands = analyzer['parseCreatedBy'](createdBy);
      
      expect(commands).toEqual(['COPY file:abc /etc/nginx/', 'RUN apt-get update']);
    });

    it('should handle empty commands', () => {
      const createdBy = '/bin/sh -c #(nop)  CMD []';
      const commands = analyzer['parseCreatedBy'](createdBy);
      
      expect(commands).toEqual(['CMD []']);
    });
  });

  describe('parseSize', () => {
    it('should parse various size formats', () => {
      expect(analyzer['parseSize('1.2GB')']).toBe(1.2 * 1024 * 1024 * 1024);
      expect(analyzer['parseSize('142.8MB')']).toBe(142.8 * 1024 * 1024);
      expect(analyzer['parseSize('512KB')']).toBe(512 * 1024);
      expect(analyzer['parseSize('1024')']).toBe(1024);
      expect(analyzer['parseSize('0')']).toBe(0);
      expect(analyzer['parseSize('')']).toBe(0);
    });
  });

  describe('package parsing', () => {
    it('should parse dpkg output correctly', () => {
      const output = `Package      Version
  nginx        1.21.0-1ubuntu1
  libc6        2.35-0ubuntu3`;

      const packages = analyzer['parseDpkgOutput'](output);
      
      expect(packages).toHaveLength(2);
      expect(packages[0]).toEqual({ name: 'nginx', version: '1.21.0-1ubuntu1', category: 'deb' });
      expect(packages[1]).toEqual({ name: 'libc6', version: '2.35-0ubuntu3', category: 'deb' });
    });

    it('should parse rpm output correctly', () => {
      const output = `nginx-1.21.0-1.el7.ngx.x86_64	123456
libc6-2.35-1.x86_64	234567`;

      const packages = analyzer['parseRpmOutput'](output);
      
      expect(packages).toHaveLength(2);
      expect(packages[0]).toEqual({ name: 'nginx', version: '1.21.0-1.el7.ngx', size: 123456, category: 'rpm' });
      expect(packages[1]).toEqual({ name: 'libc6', version: '2.35-1', size: 234567, category: 'rpm' });
    });

    it('should parse pip output correctly', () => {
      const output = `Flask==2.0.1
requests==2.25.1
numpy==1.21.0`;

      const packages = analyzer['parsePipOutput'](output);
      
      expect(packages).toHaveLength(3);
      expect(packages[0]).toEqual({ name: 'Flask', version: '2.0.1', category: 'pip' });
      expect(packages[1]).toEqual({ name: 'requests', version: '2.25.1', category: 'pip' });
      expect(packages[2]).toEqual({ name: 'numpy', version: '1.21.0', category: 'pip' });
    });

    it('should parse npm output correctly', () => {
      const output = `{
  "dependencies": {
    "express": "^4.17.1",
    "body-parser": "^1.19.0"
  }
}`;

      const packages = analyzer['parseNpmOutput'](output);
      
      expect(packages).toHaveLength(2);
      expect(packages[0]).toEqual({ name: 'express', version: '4.17.1', category: 'npm' });
      expect(packages[1]).toEqual({ name: 'body-parser', version: '1.19.0', category: 'npm' });
    });
  });
});