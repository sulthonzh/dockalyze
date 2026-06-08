#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';

import { DockerAnalyzer } from './analyzer/DockerAnalyzer';
import { SecurityScanner } from './scanner/SecurityScanner';
import { PackageManager } from './PackageManager';

// Suppress strict type checking for now
declare global {
  var vulns: any[];
}
import { SizeAnalyzer } from './analyzer/SizeAnalyzer';
import { LayerAnalyzer } from './analyzer/LayerAnalyzer';

const program = new Command();

program
  .name('dockalyze')
  .description('Docker image analyzer and security scanner')
  .version('1.0.0');

program
  .command('analyze')
  .description('Analyze a Docker image')
  .argument('<image>', 'Docker image name and tag')
  .option('-j, --json', 'Output in JSON format')
  .option('-o, --output <file>', 'Save results to file')
  .option('-v, --verbose', 'Show detailed information')
  .action(async (image: string, options: any) => {
    const spinner = ora('Analyzing Docker image...').start();
    
    try {
      const analyzer = new DockerAnalyzer();
      const result = await analyzer.analyze(image);
      
      spinner.succeed('Image analysis complete');
      
      if (options.json) {
        const output = JSON.stringify(result, null, 2);
        if (options.output) {
          require('fs').writeFileSync(options.output, output);
          console.log(chalk.green(`Results saved to: ${options.output}`));
        } else {
          console.log(output);
        }
      } else {
        displayAnalysis(result, options.verbose);
      }
    } catch (error) {
      spinner.fail(`Analysis failed: ${error.message}`);
      process.exit(1);
    }
  });

program
  .command('scan')
  .description('Scan Docker image for security vulnerabilities')
  .argument('<image>', 'Docker image name and tag')
  .option('-s, --severity <levels>', 'Filter by severity (low,medium,high,critical)', 'low,medium,high,critical')
  .option('-f, --format <json|table|markdown>', 'Output format', 'table')
  .option('-e, --exclude <packages>', 'Exclude specific packages from scanning')
  .action(async (image: string, options: any) => {
    const spinner = ora('Scanning for vulnerabilities...').start();
    
    try {
      const scanner = new SecurityScanner();
      const result = await scanner.scan(image, options);
      
      spinner.succeed('Security scan complete');
      displayScanResults(result, options.format);
    } catch (error) {
      spinner.fail(`Scan failed: ${error.message}`);
      process.exit(1);
    }
  });

program
  .command('packages')
  .description('List all installed packages in Docker image')
  .argument('<image>', 'Docker image name and tag')
  .option('-t, --tree', 'Show dependency tree')
  .option('-d, --depth <number>', 'Tree depth limit', '2')
  .option('-f, --filter <text>', 'Filter packages by name')
  .action(async (image: string, options: any) => {
    const spinner = ora('Extracting package information...').start();
    
    try {
      const pkgManager = new PackageManager();
      const result = await pkgManager.getPackages(image, options);
      
      spinner.succeed('Package extraction complete');
      displayPackages(result, options);
    } catch (error) {
      spinner.fail(`Package extraction failed: ${error.message}`);
      process.exit(1);
    }
  });

program
  .command('size')
  .description('Analyze Docker image size')
  .argument('<image>', 'Docker image name and tag')
  .option('-H, --human-readable', 'Show sizes in human-readable format')
  .option('--sort <size|name>', 'Sort results', 'size')
  .option('-t, --threshold <size>', 'Only show files larger than threshold')
  .action(async (image: string, options: any) => {
    const spinner = ora('Analyzing image size...').start();
    
    try {
      const analyzer = new SizeAnalyzer();
      const result = await analyzer.analyze(image);
      
      spinner.succeed('Size analysis complete');
      displaySizeAnalysis(result, options);
    } catch (error) {
      spinner.fail(`Size analysis failed: ${error.message}`);
      process.exit(1);
    }
  });

program
  .command('layers')
  .description('Inspect Docker image layers')
  .argument('<image>', 'Docker image name and tag')
  .option('-s, --sizes', 'Show layer sizes')
  .option('-a, --all', 'Show all layer details')
  .option('-f, --format <json|table>', 'Output format', 'table')
  .action(async (image: string, options: any) => {
    const spinner = ora('Inspecting layers...').start();
    
    try {
      const analyzer = new LayerAnalyzer();
      const result = await analyzer.analyze(image);
      
      spinner.succeed('Layer inspection complete');
      displayLayers(result, options);
    } catch (error) {
      spinner.fail(`Layer inspection failed: ${error.message}`);
      process.exit(1);
    }
  });

// Helper functions for displaying results
function displayAnalysis(result: any, verbose: boolean = false) {
  console.log(chalk.bold.blue('\n📋 Image Analysis'));
  console.log(chalk.gray(`Image: ${result.image}`));
  console.log(chalk.gray(`Size: ${formatBytes(result.size)}`));
  console.log(chalk.gray(`Layers: ${result.layers.length}`));
  
  if (verbose) {
    console.log('\n🏷️  Labels:');
    Object.entries(result.labels || {}).forEach(([key, value]) => {
      console.log(`  ${chalk.cyan(key)}: ${value}`);
    });
    
    console.log('\n🌍 Environment Variables:');
    Object.entries(result.environment || {}).forEach(([key, value]) => {
      console.log(`  ${chalk.cyan(key)}: ${value}`);
    });
  }
  
  if (result.packages && result.packages.length > 0) {
    console.log(`\n📦 Installed Packages: ${result.packages.length}`);
    const topPackages = result.packages.slice(0, verbose ? 10 : 5);
    topPackages.forEach((pkg: any) => {
      console.log(`  ${pkg.name} ${pkg.version} (${pkg.size ? formatBytes(pkg.size) : 'N/A'})`);
    });
    if (!verbose && result.packages.length > 5) {
      console.log(`  ... and ${result.packages.length - 5} more`);
    }
  }
}

function displayScanResults(result: any, format: string) {
  if (format === 'json') {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (format === 'markdown') {
    displayScanResultsMarkdown(result);
    return;
  }

  console.log(chalk.bold.blue('\n🔍 Security Scan Results'));
  console.log(chalk.gray(`Image: ${result.image}`));

  const severityColors = {
    critical: 'red',
    high: 'red',
    medium: 'yellow',
    low: 'green'
  };

  Object.entries(result.vulnerabilities || {}).forEach(([severity, vulns]) => {
    const vulnsArray = vulns as any[];
    if (vulnsArray.length > 0) {
      const color = severityColors[severity as keyof typeof severityColors] || 'white';
      console.log(`\\n🔴 ${severity.toUpperCase()} VULNERABILITIES: ${vulnsArray.length}`);
      vulnsArray.forEach((vuln: any) => {
        console.log(`  ${vuln.package} (${vuln.version})`);
        console.log(`    ${vuln.description}`);
        if (vuln.cve) {
          console.log(`    CVE: ${vuln.cve}`);
        }
      });
    }
  });
}

function displayScanResultsMarkdown(result: any) {
  const severityEmoji: Record<string, string> = {
    critical: '🔴', high: '🟠', medium: '🟡', low: '🟢'
  };

  console.log(`# Security Scan: \`${result.image}\``);
  console.log('');
  console.log(`| Severity | Count |`);
  console.log(`|----------|-------|`);
  for (const [sev, count] of Object.entries(result.summary || {})) {
    if (sev === 'total') continue;
    const emoji = severityEmoji[sev] || '⚪';
    console.log(`| ${emoji} ${sev.charAt(0).toUpperCase() + sev.slice(1)} | ${count} |`);
  }
  console.log(`| **Total** | **${result.summary?.total || 0}** |`);
  console.log('');

  const severities = ['critical', 'high', 'medium', 'low'] as const;
  for (const severity of severities) {
    const vulns = (result.vulnerabilities?.[severity] || []) as any[];
    if (vulns.length === 0) continue;

    console.log(`## ${severityEmoji[severity] || ''} ${severity.charAt(0).toUpperCase() + severity.slice(1)} (${vulns.length})`);
    console.log('');
    console.log('| Package | Version | Description | CVE |');
    console.log('|---------|---------|-------------|-----|');
    for (const v of vulns) {
      const desc = (v.description || '').replace('|', '\\|');
      const cve = v.cve ? `[${v.cve}](${v.url || '#'})` : '-';
      console.log(`| ${v.package} | ${v.version} | ${desc} | ${cve} |`);
    }
    console.log('');
  }

  console.log(`_Scanned at ${result.scannedAt}_`);
}

function displayPackages(result: any, options: any) {
  if (options.tree) {
    console.log(chalk.bold.blue('\n🌳 Package Dependency Tree'));
    console.log(chalk.gray(`Image: ${result.image} (depth: ${options.depth})`));
    displayPackageTree(result.tree, 0, options);
  } else {
    console.log(chalk.bold.blue('\n📦 Package List'));
    console.log(chalk.gray(`Image: ${result.image}`));
    
    if (result.packages && result.packages.length > 0) {
      const filter = options.filter ? new RegExp(options.filter, 'i') : null;
      const filtered = filter ? result.packages.filter((pkg: any) => filter.test(pkg.name)) : result.packages;
      
      filtered.forEach((pkg: any) => {
        console.log(`  ${pkg.name} ${pkg.version} (${pkg.size ? formatBytes(pkg.size) : 'N/A'})`);
      });
    }
  }
}

function displayPackageTree(tree: any, depth: number, options: any = {}) {
  const indent = '  '.repeat(depth);
  const arrow = depth > 0 ? '├─ ' : '';
  
  console.log(`${indent}${arrow}${tree.name} ${tree.version}`);
  
  if (tree.dependencies && depth < parseInt(options.depth)) {
    tree.dependencies.forEach((dep: any, index: number) => {
      const isLast = index === tree.dependencies.length - 1;
      const prefix = isLast ? '└─ ' : '├─ ';
      displayPackageTree({...dep, name: prefix + dep.name}, depth + 1, options);
    });
  }
}

function displaySizeAnalysis(result: any, options: any) {
  console.log(chalk.bold.blue('\n📊 Size Analysis'));
  console.log(chalk.gray(`Image: ${result.image}`));
  console.log(`Total Size: ${formatBytes(result.totalSize)}`);
  
  if (options.humanReadable) {
    if (result.largestFiles && result.largestFiles.length > 0) {
      console.log('\n🎯 Largest Files:');
      result.largestFiles.forEach((file: any) => {
        console.log(`  ${file.path} (${formatBytes(file.size)})`);
      });
    }
    
    if (result.layerSizes && result.layerSizes.length > 0) {
      console.log('\n🗂️  Layer Sizes:');
      result.layerSizes.forEach((layer: any) => {
        console.log(`  ${layer.id}: ${formatBytes(layer.size)}`);
      });
    }
  } else {
    console.log('\n🎯 Largest Files (bytes):');
    result.largestFiles?.slice(0, 10).forEach((file: any) => {
      console.log(`  ${file.path}: ${file.size}`);
    });
  }
}

function displayLayers(result: any, options: any) {
  if (options.sizes) {
    console.log(chalk.bold.blue('\n🗂️  Layer Sizes'));
    console.log(chalk.gray(`Image: ${result.image}`));
    
    result.layers.forEach((layer: any) => {
      console.log(`${layer.id}: ${formatBytes(layer.size)}`);
      if (options.all && layer.commands) {
        console.log(`  Commands: ${layer.commands.join(' | ')}`);
      }
    });
  } else {
    console.log(chalk.bold.blue('\n📋 Layer Information'));
    console.log(chalk.gray(`Image: ${result.image}`));
    
    result.layers.forEach((layer: any) => {
      console.log(`\n${layer.id}: ${formatBytes(layer.size)}`);
      if (layer.commands) {
        console.log(`  Commands: ${layer.commands.join(' | ')}`);
      }
      if (layer.diffSize) {
        console.log(`  Size change: ${formatBytes(layer.diffSize)}`);
      }
    });
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

program.parse();