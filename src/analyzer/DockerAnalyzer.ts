import { exec } from 'child_process';
const { promisify } = require('util');

const execAsync = promisify(exec);

export interface ImageAnalysis {
  image: string;
  size: number;
  layers: LayerInfo[];
  packages: PackageInfo[];
  labels: Record<string, string>;
  environment: Record<string, string>;
  created: string;
  architecture: string;
  os: string;
}

export interface LayerInfo {
  id: string;
  size: number;
  commands: string[];
  diffSize: number;
  created: string;
}

export interface PackageInfo {
  name: string;
  version: string;
  size?: number;
  description?: string;
  category?: string;
}

export class DockerAnalyzer {
  async analyze(image: string): Promise<ImageAnalysis> {
    const [sizeInfo, inspectInfo, historyInfo, packageInfo] = await Promise.all([
      this.getImageSize(image),
      this.inspectImage(image),
      this.getImageHistory(image),
      this.extractPackages(image)
    ]);

    return {
      image,
      size: sizeInfo.size,
      layers: historyInfo,
      packages: packageInfo,
      labels: inspectInfo.Config.Labels || {},
      environment: inspectInfo.Config.Env || {},
      created: inspectInfo.Created,
      architecture: inspectInfo.Architecture,
      os: inspectInfo.Os
    };
  }

  public async getImageSize(image: string): Promise<{ size: number }> {
    try {
      const { stdout } = await execAsync(`docker images ${image} --format "{{.Size}}" --no-trunc`);
      const sizeStr = stdout.trim();
      
      // Convert human-readable size to bytes
      if (sizeStr.endsWith('GB')) {
        return { size: parseFloat(sizeStr) * 1024 * 1024 * 1024 };
      } else if (sizeStr.endsWith('MB')) {
        return { size: parseFloat(sizeStr) * 1024 * 1024 };
      } else if (sizeStr.endsWith('KB')) {
        return { size: parseFloat(sizeStr) * 1024 };
      } else if (sizeStr.endsWith('B')) {
        return { size: parseFloat(sizeStr) };
      }
      
      // Try to parse as bytes directly
      const sizeBytes = parseFloat(sizeStr);
      return { size: isNaN(sizeBytes) ? 0 : sizeBytes };
    } catch (error) {
      throw new Error(`Failed to get image size: ${error.message}`);
    }
  }

  public async inspectImage(image: string): Promise<any> {
    try {
      const { stdout } = await execAsync(`docker inspect ${image}`);
      return JSON.parse(stdout)[0];
    } catch (error) {
      throw new Error(`Failed to inspect image: ${error.message}`);
    }
  }

  public async getImageHistory(image: string): Promise<LayerInfo[]> {
    try {
      const { stdout } = await execAsync(`docker history --no-trunc --format "{{.ID}}\t{{.Size}}\t{{.CreatedBy}}" ${image}`);
      const lines = stdout.trim().split('\n');
      
      return lines.map((line: string, index: number) => {
        const [id, sizeStr, createdBy] = line.split('\t');
        const commands = createdBy ? this.parseCreatedBy(createdBy) : [];
        
        return {
          id,
          size: this.parseSize(sizeStr),
          commands,
          diffSize: index === 0 ? 0 : this.parseSize(lines[index - 1]?.split('\t')[1] || '0'),
          created: new Date(Date.now() - index * 86400000).toISOString()
        };
      }).filter(layer => layer.id && layer.size > 0);
    } catch (error) {
      throw new Error(`Failed to get image history: ${error.message}`);
    }
  }

  public async extractPackages(image: string): Promise<PackageInfo[]> {
    // This is a simplified implementation
    // In a real implementation, you would need to handle different package managers
    try {
      // Try to extract package information from common package managers
      const packages: PackageInfo[] = [];
      
      // Check for Debian/Ubuntu packages
      try {
        const { stdout } = await execAsync(`docker run --rm ${image} dpkg-query -W 2>/dev/null || echo "No dpkg"`);
        if (stdout !== 'No dpkg\n') {
          const debPackages = this.parseDpkgOutput(stdout);
          packages.push(...debPackages);
        }
      } catch (error) {
        // No dpkg available, continue
      }
      
      // Check for RPM packages (RedHat/CentOS)
      try {
        const { stdout } = await execAsync(`docker run --rm ${image} rpm -qa --queryformat '%{NAME}\t%{VERSION}\t%{SIZE}\n' 2>/dev/null || echo "No rpm"`);
        if (stdout !== 'No rpm\n') {
          const rpmPackages = this.parseRpmOutput(stdout);
          packages.push(...rpmPackages);
        }
      } catch (error) {
        // No rpm available, continue
      }
      
      // Check for Python packages
      try {
        const { stdout } = await execAsync(`docker run --rm ${image} pip list --format=freeze 2>/dev/null || echo "No pip"`);
        if (stdout !== 'No pip\n') {
          const pipPackages = this.parsePipOutput(stdout);
          packages.push(...pipPackages);
        }
      } catch (error) {
        // No pip available, continue
      }
      
      // Check for Node.js packages
      try {
        const { stdout } = await execAsync(`docker run --rm ${image} npm list --depth=0 --json 2>/dev/null || echo "No npm"`);
        if (stdout !== 'No npm\n' && stdout !== '{}') {
          const npmPackages = this.parseNpmOutput(stdout);
          packages.push(...npmPackages);
        }
      } catch (error) {
        // No npm available, continue
      }
      
      return packages;
    } catch (error) {
      throw new Error(`Failed to extract packages: ${error.message}`);
    }
  }

  public parseCreatedBy(createdBy: string): string[] {
    // Extract actual commands from the "CreatedBy" field
    return createdBy
      .split(' /bin/sh -c ')
      .slice(1)
      .map(cmd => cmd.replace(/^(#( ?)|)/, ''))
      .filter(cmd => cmd.length > 0)
      .map(cmd => {
        // Limit command length for display
        return cmd.length > 50 ? cmd.substring(0, 47) + '...' : cmd;
      });
  }

  public parseSize(sizeStr: string): number {
    if (!sizeStr || sizeStr === '0') return 0;
    
    const cleanStr = sizeStr.trim();
    if (cleanStr.endsWith('GB')) {
      return parseFloat(cleanStr) * 1024 * 1024 * 1024;
    } else if (cleanStr.endsWith('MB')) {
      return parseFloat(cleanStr) * 1024 * 1024;
    } else if (cleanStr.endsWith('KB')) {
      return parseFloat(cleanStr) * 1024;
    } else if (cleanStr.endsWith('B')) {
      return parseFloat(cleanStr);
    }
    
    // Try to parse as bytes directly
    const sizeBytes = parseFloat(cleanStr);
    return isNaN(sizeBytes) ? 0 : sizeBytes;
  }

  public parseDpkgOutput(output: string): PackageInfo[] {
    return output.split('\n')
      .filter(line => line && line.trim())
      .map(line => {
        const [name, version] = line.split('\t');
        return {
          name: name || line,
          version: version || 'unknown',
          category: 'deb'
        };
      });
  }

  public parseRpmOutput(output: string): PackageInfo[] {
    return output.split('\n')
      .filter(line => line && line.trim())
      .map(line => {
        const [name, version, size] = line.split('\t');
        return {
          name: name || line,
          version: version || 'unknown',
          size: size ? parseInt(size) : undefined,
          category: 'rpm'
        };
      });
  }

  public parsePipOutput(output: string): PackageInfo[] {
    return output.split('\n')
      .filter(line => line && line.trim())
      .map(line => {
        const [name, version] = line.split('==');
        return {
          name: name || line,
          version: version || 'unknown',
          category: 'pip'
        };
      });
  }

  public parseNpmOutput(output: string): PackageInfo[] {
    try {
      const data = JSON.parse(output);
      const packages: PackageInfo[] = [];
      
      Object.entries(data.dependencies || {}).forEach(([name, info]: [string, any]) => {
        packages.push({
          name,
          version: info.version || 'unknown',
          category: 'npm'
        });
      });
      
      return packages;
    } catch (error) {
      return [];
    }
  }
}