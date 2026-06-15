import { exec } from 'child_process';
const { promisify } = require('util');

const execAsync = promisify(exec);

export interface LayerInfo {
  id: string;
  size: number;
  commands: string[];
  diffSize: number;
  created: string;
  parent?: string;
  labels?: Record<string, string>;
}

export interface LayerAnalysis {
  image: string;
  totalLayers: number;
  totalSize: number;
  layers: LayerInfo[];
  layerDistribution: {
    small: number;
    medium: number;
    large: number;
    huge: number;
  };
  buildTimes: Array<{
    layerId: string;
    time: number;
    commands: string[];
  }>;
}

export class LayerAnalyzer {
  async analyze(image: string): Promise<LayerAnalysis> {
    const [imageInfo, historyInfo, manifestInfo] = await Promise.all([
      this.getImageInfo(image),
      this.getImageHistory(image),
      this.getImageManifest(image)
    ]);

    const layerDistribution = this.analyzeLayerDistribution(historyInfo);
    const buildTimes = this.analyzeBuildTimes(historyInfo);

    return {
      image,
      totalLayers: historyInfo.length,
      totalSize: historyInfo.reduce((sum, layer) => sum + layer.size, 0),
      layers: historyInfo,
      layerDistribution,
      buildTimes
    };
  }

  public async getImageInfo(image: string): Promise<any> {
    try {
      const { stdout } = await execAsync(`docker inspect ${image}`);
      return JSON.parse(stdout)[0];
    } catch (error) {
      throw new Error(`Failed to get image info: ${error.message}`);
    }
  }

  public async getImageHistory(image: string): Promise<LayerInfo[]> {
    try {
      const { stdout } = await execAsync(`docker history --no-trunc --format "{{.ID}}\t{{.Size}}\t{{.CreatedBy}}\t{{.Created}}" ${image}`);
      const lines = stdout.trim().split('\n');
      
      return lines.map((line: string, index: number) => {
        const [id, sizeStr, createdBy, created] = line.split('\t');
        const commands = this.parseCreatedBy(createdBy);
        
        return {
          id,
          size: this.parseSize(sizeStr),
          commands,
          diffSize: index === 0 ? 0 : this.parseSize(lines[index - 1]?.split('\t')[1] || '0'),
          created: this.parseCreatedDate(created),
          parent: index > 0 ? lines[index - 1]?.split('\t')[0] : undefined
        };
      }).filter(layer => layer.id && layer.size > 0);
    } catch (error) {
      throw new Error(`Failed to get image history: ${error.message}`);
    }
  }

  public async getImageManifest(image: string): Promise<any> {
    try {
      const { stdout } = await execAsync(`docker manifest inspect ${image} 2>/dev/null || echo "No manifest"`);
      if (stdout.trim() !== 'No manifest') {
        return JSON.parse(stdout);
      }
    } catch (error) {
      // Manifest not available, continue without it
    }
    return null;
  }

  public parseCreatedBy(createdBy: string): string[] {
    if (!createdBy || createdBy === '<missing>') return [];
    
    const commands = createdBy
      .split(' /bin/sh -c ')
      .slice(1)
      .map(cmd => cmd.replace(/^(#( ?)|)/, ''))
      .filter(cmd => cmd.length > 0)
      .map(cmd => {
        return cmd.length > 50 ? cmd.substring(0, 47) + '...' : cmd;
      });
    
    return commands;
  }

  public parseSize(sizeStr: string): number {
    if (!sizeStr || sizeStr === '0' || sizeStr === '0B') return 0;
    
    const cleanStr = sizeStr.trim().toUpperCase();
    if (cleanStr.endsWith('GB')) {
      return parseFloat(cleanStr) * 1024 * 1024 * 1024;
    } else if (cleanStr.endsWith('MB')) {
      return parseFloat(cleanStr) * 1024 * 1024;
    } else if (cleanStr.endsWith('KB')) {
      return parseFloat(cleanStr) * 1024;
    } else if (cleanStr.endsWith('B')) {
      return parseFloat(cleanStr);
    }
    
    const sizeBytes = parseFloat(cleanStr);
    return isNaN(sizeBytes) ? 0 : sizeBytes;
  }

  public parseCreatedDate(createdStr: string): string {
    if (!createdStr || createdStr === '0001-01-01 00:00:00 +0000 UTC') {
      return new Date().toISOString();
    }
    
    try {
      const date = new Date(createdStr);
      return date.toISOString();
    } catch (error) {
      return new Date().toISOString();
    }
  }

  public analyzeLayerDistribution(layers: LayerInfo[]) {
    const distribution = {
      small: 0,
      medium: 0,
      large: 0,
      huge: 0
    };
    
    layers.forEach(layer => {
      if (layer.size < 1024 * 1024) { // < 1MB
        distribution.small++;
      } else if (layer.size < 10 * 1024 * 1024) { // 1MB - 10MB
        distribution.medium++;
      } else if (layer.size < 100 * 1024 * 1024) { // 10MB - 100MB
        distribution.large++;
      } else { // > 100MB
        distribution.huge++;
      }
    });
    
    return distribution;
  }

  public analyzeBuildTimes(layers: LayerInfo[]): Array<{ layerId: string; time: number; commands: string[] }> {
    return layers.map(layer => ({
      layerId: layer.id,
      time: Math.random() * 60 + 10, // Simulated build time between 10-70 seconds
      commands: layer.commands
    }));
  }

  public analyzeOptimization(layers: LayerInfo[]): {
    opportunities: Array<{
      layerId: string;
      issue: string;
      suggestion: string;
      potentialSavings: number;
    }>;
    recommendations: string[];
  } {
    const opportunities: Array<{
      layerId: string;
      issue: string;
      suggestion: string;
      potentialSavings: number;
    }> = [];
    
    const recommendations: string[] = [];
    
    layers.filter(layer => layer.size > 50 * 1024 * 1024).forEach(layer => {
      opportunities.push({
        layerId: layer.id,
        issue: 'Large layer size',
        suggestion: 'Split layer into smaller, more focused layers',
        potentialSavings: layer.size * 0.3 // Estimated 30% reduction
      });
      
      recommendations.push(`Layer ${layer.id.substring(0, 12)} is ${this.formatSize(layer.size)}. Consider splitting into smaller layers.`);
    });
    
    layers.filter(layer => layer.commands.length > 3).forEach(layer => {
      opportunities.push({
        layerId: layer.id,
        issue: 'Multiple commands in single layer',
        suggestion: 'Separate RUN commands into individual layers',
        potentialSavings: layer.size * 0.2 // Estimated 20% reduction
      });
      
      recommendations.push(`Layer ${layer.id.substring(0, 12)} has ${layer.commands.length} commands. Separate RUN commands into individual layers.`);
    });
    
    const consecutiveCopyLayers = this.findConsecutiveCopyLayers(layers);
    if (consecutiveCopyLayers.length > 1) {
      recommendations.push('Consider combining COPY/ADD commands to improve build caching.');
    }
    
    return { opportunities, recommendations };
  }

  public findConsecutiveCopyLayers(layers: LayerInfo[]): LayerInfo[] {
    const copyLayers: LayerInfo[] = [];
    
    layers.forEach(layer => {
      const hasCopyCommand = layer.commands.some(cmd => 
        cmd.includes('COPY') || cmd.includes('ADD') || cmd.includes('download')
      );
      
      if (hasCopyCommand) {
        copyLayers.push(layer);
      }
    });
    
    return copyLayers;
  }

  formatSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const sizeIndex = Math.floor(Math.log(bytes) / Math.log(1024));
    const sizeValue = bytes / Math.pow(1024, sizeIndex);
    
    return `${sizeValue.toFixed(2)} ${units[sizeIndex]}`;
  }
}