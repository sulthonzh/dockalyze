# dockalyze - Docker Image Analyzer & Security Scanner

A zero-dependency Docker image analyzer and security scanner that helps you understand what's inside your containers and identify potential security risks.

## Why dockalyze?

When you're running containers in production, you need to know:
- What packages are installed and which ones are outdated?
- What security vulnerabilities exist in your base images?
- How big is your image and what's taking up space?
- What's the actual attack surface of your container?

dockalyze gives you all this in one simple CLI tool.

## Features

- **Image Analysis**: Inspect Docker images without running containers
- **Security Scanning**: Detect vulnerabilities in packages and base images
- **Size Analysis**: Find out what's making your Docker images large
- **Layer Inspection**: Understand how your Docker layers are structured
- **Package Discovery**: List all installed packages with versions
- **Dependency Tree**: See package relationships and transitive dependencies
- **CVE Detection**: Check for known security vulnerabilities
- **Image Metadata**: Extract labels, environment variables, and build info
- **Multiple Output Formats**: JSON, pretty tables, and markdown reports

## Installation

```bash
npm install -g dockalyze
```

Or use directly without installation:

```bash
npx dockalyze
```

## Quick Start

### Basic Image Analysis

```bash
# Analyze a Docker image
dockalyze analyze nginx:latest

# Get detailed package information
dockalyze packages nginx:latest

# Check for security vulnerabilities
dockalyze scan nginx:latest
```

### Size Analysis

```bash
# See what's taking up space
dockalyze size nginx:latest

# Get size breakdown by layer
dockalyze layers nginx:latest
```

## Usage

### Analyze Command

```bash
dockalyze analyze <image> [options]
```

Analyze a Docker image and get comprehensive information:

```bash
dockalyze analyze nginx:latest --json --output report.json
```

Options:
- `--json` - Output in JSON format
- `--output <file>` - Save results to file
- `--verbose` - Show detailed information

### Scan Command

```bash
dockalyze scan <image> [options]
```

Scan for security vulnerabilities:

```bash
dockalyze scan nginx:latest --severity critical,high
dockalyze scan my-app:1.0.0 --format json
```

Options:
- `--severity <levels>` - Filter by severity (low,medium,high,critical)
- `--format <json|table|markdown>` - Output format
- `--exclude <packages>` - Exclude specific packages from scanning

### Packages Command

```bash
dockalyze packages <image> [options]
```

List all installed packages:

```bash
dockalyze packages nginx:latest --tree
dockalyze packages alpine:latest --depth 2
```

Options:
- `--tree` - Show dependency tree
- `--depth <number>` - Tree depth limit
- `--filter <text>` - Filter packages by name

### Size Command

```bash
dockalyze size <image> [options]
```

Analyze image size:

```bash
dockalyze size nginx:latest --human-readable
dockalyze size my-app:1.0.0 --sort size
```

Options:
- `--human-readable` - Show sizes in human-readable format
- `--sort <size|name>` - Sort results
- `--threshold <size>` - Only show files larger than threshold

### Layers Command

```bash
dockalyze layers <image> [options]
```

Inspect Docker layers:

```bash
dockalyze layers nginx:latest --sizes
dockalyze layers my-app:1.0.0 --all
```

Options:
- `--sizes` - Show layer sizes
- `--all` - Show all layer details
- `--format <json|table>` - Output format

## Examples

### Basic Security Scan

```bash
dockalyze scan ubuntu:22.04
```

Output:
```
📋 Security Scan Results for ubuntu:22.04

🔴 Critical Vulnerabilities: 3
   - openssl (3.0.2-1ubuntu1) - CVE-2023-3817
   - curl (7.81.0-1ubuntu1.18.04.1) - CVE-2023-27533
   - libcurl (7.81.0-1ubuntu1.18.04.1) - CVE-2023-27533

🟠 High Vulnerabilities: 12
   - wget (1.21.3-1ubuntu1) - CVE-2023-25136
   - apt (2.4.13) - CVE-2023-27544
   - ... (truncated)

🟡 Medium Vulnerabilities: 23
🟢 Low Vulnerabilities: 45
```

### Package Tree Analysis

```bash
dockalyze packages node:18 --tree --depth 2
```

Output:
```
📦 Package Tree for node:18 (depth: 2)

node (18.17.0)
├── libuuid (1.0.3)
├── python3 (3.11.2)
│   ├── libffi (3.4.2)
│   └── libpython3.11 (3.11.2)
├── xz-utils (5.2.5)
├── ca-certificates (20230311)
│   └── ca-certificates (20230311)
└── tzdata (2023c)
    └── tzdata (2023c)
```

### Size Analysis

```bash
dockalyze size nginx:latest --human-readable --sort size
```

Output:
```
📊 Image Size Analysis for nginx:latest

🗂️  Total Size: 142.8MB

📁 Layer Breakdown:
  1.0MB  /usr/share/nginx/html/
  32.4MB  /usr/sbin/nginx
  18.2MB  /etc/nginx/
  12.8MB  /var/log/nginx/
   8.5MB  /usr/lib/nginx/modules/
   6.2MB  /usr/bin/
   4.1MB  /bin/
   3.7MB  /lib/x86_64-linux-gnu/
   2.8MB  /usr/lib/
   1.9MB  /lib/
   ... (remaining files)

🎯 Largest Files:
  - /usr/sbin/nginx (32.4MB)
  - /usr/lib/x86_64-linux-gnu/libssl.so.3 (18.7MB)
  - /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (16.2MB)
```

## API

```javascript
const dockalyze = require('dockalyze');

// Analyze an image
const analysis = await dockalyze.analyze('nginx:latest');
console.log(analysis.packages);
console.log(analysis.layers);
console.log(analysis.security);

// Scan for vulnerabilities
const scan = await dockalyze.scan('ubuntu:22.04');
console.log(scan.vulnerabilities);

// Get package information
const packages = await dockalyze.packages('node:18');
console.log(packages.list);
console.log(packages.tree);
```

## Development

```bash
git clone https://github.com/sulthonzh/dockalyze
cd dockalyze
npm install
npm test
```

## Roadmap

- [ ] Multi-architecture image support
- [ ] SBOM generation (Software Bill of Materials)
- [ ] Integration with vulnerability databases
- [ ] Container runtime analysis
- [ ] Kubernetes pod analysis
- [ ] Performance benchmarking
- [ ] Image comparison tools

## License

MIT - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Support

If you find this tool useful, consider starring it on GitHub! 🙏

---