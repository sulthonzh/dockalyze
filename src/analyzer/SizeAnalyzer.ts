import { exec } from 'child_process';
const { promisify } = require('util');

const execAsync = promisify(exec);

export interface LayerSize {
  id: string;
  size: number;
  commands?: string[];
}

export interface SizeAnalysis {
  image: string;
  totalSize: number;
  layerSizes: LayerSize[];
  largestFiles: Array<{
    path: string;
    size: number;
    layerId?: string;
  }>;
  sizeDistribution: {
    small: number;    // < 1KB
    medium: number;  // 1KB - 1MB
    large: number;   // 1MB - 100MB
    huge: number;    // > 100MB
  };
}

export class SizeAnalyzer {
  async analyze(image: string): Promise<SizeAnalysis> {
    const [totalSize, layerSizes, fileSizes] = await Promise.all([
      this.getImageSize(image),
      this.getLayerSizes(image),
      this.getFileSizes(image)
    ]);

    const largestFiles = this.getLargestFiles(fileSizes);
    const sizeDistribution = this.analyzeSizeDistribution(fileSizes);

    return {
      image,
      totalSize,
      layerSizes,
      largestFiles,
      sizeDistribution
    };
  }

  public async getImageSize(image: string): Promise<number> {
    try {
      const { stdout } = await execAsync(`docker images ${image} --format "{{.Size}}" --no-trunc`);
      const sizeStr = stdout.trim();
      
      return this.parseHumanReadableSize(sizeStr);
    } catch (error) {
      throw new Error(`Failed to get image size: ${error.message}`);
    }
  }

  public async getLayerSizes(image: string): Promise<LayerSize[]> {
    try {
      const { stdout } = await execAsync(`docker history --no-trunc --format "{{.ID}}\t{{.Size}}\t{{.CreatedBy}}" ${image}`);
      const lines = stdout.trim().split('\n');
      
      return lines.map((line: string) => {
        const [id, sizeStr, createdBy] = line.split('\t');
        const commands = createdBy ? this.parseCreatedBy(createdBy) : [];
        
        return {
          id,
          size: this.parseHumanReadableSize(sizeStr),
          commands
        };
      }).filter(layer => layer.id && layer.size > 0);
    } catch (error) {
      throw new Error(`Failed to get layer sizes: ${error.message}`);
    }
  }

  public async getFileSizes(image: string): Promise<Array<{ path: string; size: number; layerId?: string }>> {
    const files: Array<{ path: string; size: number; layerId?: string }> = [];
    
    try {
      // Create a temporary container to inspect files
      const containerId = await this.createTemporaryContainer(image);
      
      try {
        // Get file sizes using du command
        const { stdout } = await execAsync(`docker exec ${containerId} find / -type f -exec du -b {} \\; 2>/dev/null || echo "No files found"`);
        
        if (stdout.trim() !== 'No files found') {
          const lines = stdout.trim().split('\n');
          lines.forEach(line => {
            const [sizeStr, path] = line.split('\t');
            if (sizeStr && path) {
              files.push({
                path,
                size: parseInt(sizeStr)
              });
            }
          });
        }
        
        // Also get layer-specific file information
        await this.addLayerFileInfo(containerId, files);
        
      } finally {
        // Clean up the temporary container
        await execAsync(`docker rm -f ${containerId}`).catch(() => {
          // Container already removed or failed to remove
        });
      }
    } catch (error) {
      console.warn(`File size analysis failed: ${error.message}`);
    }
    
    return files;
  }

  public async createTemporaryContainer(image: string): Promise<string> {
    try {
      const { stdout } = await execAsync(`docker create --entrypoint /bin/sh ${image}`);
      return stdout.trim();
    } catch (error) {
      throw new Error(`Failed to create temporary container: ${error.message}`);
    }
  }

  public async addLayerFileInfo(containerId: string, files: Array<{ path: string; size: number; layerId?: string }>): Promise<void> {
    try {
      // Get file sizes for each layer using docker diff
      const { stdout: diffOutput } = await execAsync(`docker diff ${containerId}`);
      const changedFiles = diffOutput.trim().split('\n').filter(line => line.startsWith('A') || line.startsWith('M'));
      
      // Add layer information to files
      changedFiles.forEach(line => {
        const fileOp = line.charAt(0);
        const filePath = line.substring(2);
        files.push({
          path: filePath,
          size: 0, // Size will be calculated elsewhere
          layerId: 'unknown'
        });
      });
      
    } catch (error) {
      // Layer information extraction failed, continue without it
    }
  }

  public parseCreatedBy(createdBy: string): string[] {
    return createdBy
      .split(' /bin/sh -c ')
      .slice(1)
      .map(cmd => cmd.replace(/^(#( ?)|)/, ''))
      .filter(cmd => cmd.length > 0)
      .map(cmd => {
        return cmd.length > 50 ? cmd.substring(0, 47) + '...' : cmd;
      });
  }

  public parseHumanReadableSize(sizeStr: string): number {
    if (!sizeStr || sizeStr === '0') return 0;
    
    const cleanStr = sizeStr.trim();
    const multiplier = cleanStr.toUpperCase().includes('GB') ? 1024 * 1024 * 1024 :
                      cleanStr.toUpperCase().includes('MB') ? 1024 * 1024 :
                      cleanStr.toUpperCase().includes('KB') ? 1024 :
                      1;
    
    const numericValue = parseFloat(cleanStr.replace(/[^\d.]/g, ''));
    return isNaN(numericValue) ? 0 : Math.round(numericValue * multiplier);
  }

  public getLargestFiles(files: Array<{ path: string; size: number; layerId?: string }>, limit: number = 20): Array<{ path: string; size: number; layerId?: string }> {
    return files
      .sort((a, b) => b.size - a.size)
      .slice(0, limit)
      .map(file => ({
        path: file.path,
        size: file.size,
        layerId: file.layerId
      }));
  }

  public analyzeSizeDistribution(files: Array<{ path: string; size: number }>) {
    const distribution = {
      small: 0,    // < 1KB
      medium: 0,  // 1KB - 1MB
      large: 0,   // 1MB - 100MB
      huge: 0     // > 100MB
    };
    
    files.forEach(file => {
      if (file.size < 1024) {
        distribution.small++;
      } else if (file.size < 1024 * 1024) {
        distribution.medium++;
      } else if (file.size < 100 * 1024 * 1024) {
        distribution.large++;
      } else {
        distribution.huge++;
      }
    });
    
    return distribution;
  }

  // Utility method for human-readable size formatting
  formatSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const sizeIndex = Math.floor(Math.log(bytes) / Math.log(1024));
    const sizeValue = bytes / Math.pow(1024, sizeIndex);
    
    return `${sizeValue.toFixed(2)} ${units[sizeIndex]}`;
  }
}