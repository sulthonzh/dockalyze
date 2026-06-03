import { exec } from 'child_process';
const { promisify } = require('util');

const execAsync = promisify(exec);

export interface PackageTree {
  name: string;
  version: string;
  dependencies?: PackageTree[];
  size?: number;
  category?: string;
}

export interface PackageResult {
  image: string;
  packages: Array<{
    name: string;
    version: string;
    size?: number;
    category?: string;
  }>;
  tree?: PackageTree;
}

export class PackageManager {
  async getPackages(image: string, options: { tree?: boolean; depth?: number; filter?: string } = {}): Promise<PackageResult> {
    const { tree = false, depth = 2, filter } = options;
    
    const packages = await this.extractPackages(image);
    
    let result: PackageResult = {
      image,
      packages
    };
    
    if (tree) {
      result.tree = this.buildPackageTree(packages);
      this.limitTreeDepth(result.tree, depth);
    }
    
    if (filter) {
      result.packages = packages.filter(pkg => 
        pkg.name.toLowerCase().includes(filter.toLowerCase())
      );
    }
    
    return result;
  }

  public async extractPackages(image: string): Promise<Array<{ name: string; version: string; size?: number; category?: string }>> {
    const packages: Array<{ name: string; version: string; size?: number; category?: string }> = [];
    
    try {
      // Try to run a temporary container to extract package information
      const { stdout: containerOutput } = await execAsync(`docker run --rm ${image} 2>&1 || echo "Container exited"`);
      
      // Extract packages from different package managers
      packages.push(...this.extractDebianPackages(containerOutput));
      packages.push(...this.extractRpmPackages(containerOutput));
      packages.push(...this.extractPythonPackages(containerOutput));
      packages.push(...this.extractNodePackages(containerOutput));
      packages.push(...this.extractGoPackages(containerOutput));
      packages.push(...this.extractRustPackages(containerOutput));
      packages.push(...this.extractJavaPackages(containerOutput));
      
      // If no packages found, try package-specific commands
      if (packages.length === 0) {
        await this.tryPackageSpecificCommands(image, packages);
      }
      
    } catch (error) {
      console.warn(`Package extraction failed: ${error.message}`);
    }
    
    return packages;
  }

  public extractDebianPackages(output: string): Array<{ name: string; version: string; size?: number; category?: string }> {
    const packages: Array<{ name: string; version: string; size?: number; category?: string }> = [];
    
    // Look for dpkg -W output
    const dpkgPattern = /^([a-zA-Z0-9][a-zA-Z0-9+\-.]*)\t([0-9][0-9a-zA-Z.:+~-]*)/gm;
    let match;
    
    while ((match = dpkgPattern.exec(output)) !== null) {
      packages.push({
        name: match[1],
        version: match[2],
        category: 'deb'
      });
    }
    
    // Look for apt list output
    const aptPattern = /^([a-zA-Z0-9][a-zA-Z0-9+\-.]*)\s+\[([^\]]+)\]\s+([0-9][0-9a-zA-Z.:+~-]*)/gm;
    while ((match = aptPattern.exec(output)) !== null) {
      packages.push({
        name: match[1],
        version: match[2],
        category: 'apt'
      });
    }
    
    return packages;
  }

  public extractRpmPackages(output: string): Array<{ name: string; version: string; size?: number; category?: string }> {
    const packages: Array<{ name: string; version: string; size?: number; category?: string }> = [];
    
    // Look for rpm -qa output
    const rpmPattern = /^([a-zA-Z0-9][a-zA-Z0-9+\-_]*)-([0-9][0-9a-zA-Z.~_-]*)/gm;
    let match;
    
    while ((match = rpmPattern.exec(output)) !== null) {
      packages.push({
        name: match[1],
        version: match[2],
        category: 'rpm'
      });
    }
    
    // Look for yum list output
    const yumPattern = /^([a-zA-Z0-9][a-zA-Z0-9+\-_\.]+)\.\w+\s+([0-9][0-9a-zA-Z.~_-]*)/gm;
    while ((match = yumPattern.exec(output)) !== null) {
      packages.push({
        name: match[1],
        version: match[2],
        category: 'yum'
      });
    }
    
    return packages;
  }

  public extractPythonPackages(output: string): Array<{ name: string; version: string; size?: number; category?: string }> {
    const packages: Array<{ name: string; version: string; size?: number; category?: string }> = [];
    
    // Look for pip list output
    const pipPattern = /^([a-zA-Z0-9][a-zA-Z0-9+\-_\.]*)\s+([0-9][0-9a-zA-Z.~_+-]*)/gm;
    let match;
    
    while ((match = pipPattern.exec(output)) !== null) {
      packages.push({
        name: match[1],
        version: match[2],
        category: 'pip'
      });
    }
    
    return packages;
  }

  public extractNodePackages(output: string): Array<{ name: string; version: string; size?: number; category?: string }> {
    const packages: Array<{ name: string; version: string; size?: number; category?: string }> = [];
    
    // Look for package.json output
    const packageJsonPattern = /"([a-zA-Z0-9][a-zA-Z0-9+\-_\.]*)"\s*:\s*"([0-9][0-9a-zA-Z.~_+-]*)"/gm;
    let match;
    
    while ((match = packageJsonPattern.exec(output)) !== null) {
      packages.push({
        name: match[1],
        version: match[2],
        category: 'npm'
      });
    }
    
    return packages;
  }

  public extractGoPackages(output: string): Array<{ name: string; version: string; size?: number; category?: string }> {
    const packages: Array<{ name: string; version: string; size?: number; category?: string }> = [];
    
    // Look for go.mod output
    const goModPattern = /^([a-zA-Z0-9][a-zA-Z0-9\/\._-]+)\s+([0-9][0-9a-zA-Z.~_+-]*)$/gm;
    let match;
    
    while ((match = goModPattern.exec(output)) !== null) {
      packages.push({
        name: match[1],
        version: match[2],
        category: 'go'
      });
    }
    
    return packages;
  }

  public extractRustPackages(output: string): Array<{ name: string; version: string; size?: number; category?: string }> {
    // Rust package extraction would require Cargo.toml parsing
    // For now, return empty array
    return [];
  }

  public extractJavaPackages(output: string): Array<{ name: string; version: string; size?: number; category?: string }> {
    // Java package extraction would require parsing various manifests
    // For now, return empty array
    return [];
  }

  public async tryPackageSpecificCommands(image: string, packages: Array<{ name: string; version: string; size?: number; category?: string }>): Promise<void> {
    const commands = [
      { cmd: 'dpkg-query -W', category: 'deb' },
      { cmd: 'rpm -qa --queryformat "%{NAME}\t%{VERSION}\n"', category: 'rpm' },
      { cmd: 'pip list --format=freeze', category: 'pip' },
      { cmd: 'npm list --depth=0 --json', category: 'npm' },
      { cmd: 'go list -m all', category: 'go' }
    ];
    
    for (const { cmd, category } of commands) {
      try {
        const { stdout } = await execAsync(`docker run --rm ${image} ${cmd} 2>/dev/null || echo "No ${category}"`);
        
        if (stdout.trim() !== `No ${category}`) {
          const extracted = this.parsePackageOutput(stdout, category);
          packages.push(...extracted);
        }
      } catch (error) {
        // Command failed, continue
      }
    }
  }

  public parsePackageOutput(output: string, category: string): Array<{ name: string; version: string; size?: number; category?: string }> {
    const packages: Array<{ name: string; version: string; size?: number; category?: string }> = [];
    
    switch (category) {
      case 'deb':
        const debPattern = /^([a-zA-Z0-9][a-zA-Z0-9+\-.]*)\t([0-9][0-9a-zA-Z.:+~-]*)/gm;
        let match;
        while ((match = debPattern.exec(output)) !== null) {
          packages.push({
            name: match[1],
            version: match[2],
            category
          });
        }
        break;
        
      case 'rpm':
        const rpmPattern = /^([a-zA-Z0-9][a-zA-Z0-9+\-_]*)\t([0-9][0-9a-zA-Z.~_-]*)/gm;
        while ((match = rpmPattern.exec(output)) !== null) {
          packages.push({
            name: match[1],
            version: match[2],
            category
          });
        }
        break;
        
      case 'pip':
        const pipPattern = /^([a-zA-Z0-9][a-zA-Z0-9+\-_\.]*)==([0-9][0-9a-zA-Z.~_+-]*)/gm;
        while ((match = pipPattern.exec(output)) !== null) {
          packages.push({
            name: match[1],
            version: match[2],
            category
          });
        }
        break;
        
      case 'npm':
        try {
          const npmData = JSON.parse(output);
          Object.entries(npmData.dependencies || {}).forEach(([name, info]: [string, any]) => {
            packages.push({
              name,
              version: info.version || 'unknown',
              category
            });
          });
        } catch (error) {
          // JSON parsing failed, skip
        }
        break;
        
      case 'go':
        const goPattern = /^([a-zA-Z0-9][a-zA-Z0-9\/\._-]+)\s+([0-9][0-9a-zA-Z.~_+-]*)$/gm;
        while ((match = goPattern.exec(output)) !== null) {
          packages.push({
            name: match[1],
            version: match[2],
            category
          });
        }
        break;
    }
    
    return packages;
  }

  public buildPackageTree(packages: Array<{ name: string; version: string; size?: number; category?: string }>): PackageTree {
    const tree: PackageTree = {
      name: 'root',
      version: '1.0.0',
      dependencies: []
    };
    
    // Build dependency relationships (simplified)
    // In a real implementation, you'd need to parse actual dependency information
    packages.forEach(pkg => {
      // For demo purposes, create a simple tree structure
      const node: PackageTree = {
        name: pkg.name,
        version: pkg.version,
        size: pkg.size,
        category: pkg.category
      };
      
      // Add some basic dependencies (this would be data-driven in a real implementation)
      if (pkg.name.startsWith('node') || pkg.name === 'npm') {
        node.dependencies = [
          { name: 'libuv', version: '1.44.0', category: 'system' },
          { name: 'openssl', version: '1.1.1k', category: 'system' }
        ];
      } else if (pkg.name.startsWith('python')) {
        node.dependencies = [
          { name: 'libpython3', version: '3.11.0', category: 'system' },
          { name: 'sqlite3', version: '3.40.0', category: 'system' }
        ];
      }
      
      tree.dependencies?.push(node);
    });
    
    return tree;
  }

  public limitTreeDepth(tree: PackageTree, depth: number): void {
    if (depth <= 0 || !tree.dependencies) return;
    
    tree.dependencies.forEach(dep => {
      this.limitTreeDepth(dep, depth - 1);
      if (depth === 1) {
        dep.dependencies = undefined;
      }
    });
  }
}