const Analyzer = require('../src/core/analyzer');
const Scanner = require('../src/core/scanner');
const Detector = require('../src/core/detector');

jest.mock('../src/core/scanner');
jest.mock('../src/core/detector');

describe('Integration Tests', () => {
  test('complete package analysis workflow', async () => {
    const analyzer = new Analyzer();
    const packageName = 'test-package';
    
    // Mock all external calls
    Scanner.prototype.scanPackage.mockResolvedValue({
      score: 85,
      basicInfo: { name: packageName, version: '1.0.0' },
      vulnerabilities: { critical: [] },
      securityMetrics: { hasSuspiciousScripts: false }
    });
    
    Detector.prototype.analyzeTarball.mockResolvedValue({
      malwareDetected: false,
      suspiciousPatterns: [],
      risks: [],
      score: 90
    });
    
    const results = await analyzer.analyzePackage(packageName);
    
    expect(results.score).toBeDefined();
    expect(results.malwareDetected).toBe(false);
    expect(results.basicInfo.name).toBe(packageName);
  });

  test('handles complete analysis failure', async () => {
    const analyzer = new Analyzer();
    
    Scanner.prototype.scanPackage.mockRejectedValue(new Error('Network error'));
    Detector.prototype.analyzeTarball.mockRejectedValue(new Error('Analysis failed'));
    
    await expect(analyzer.analyzePackage('test-package'))
      .rejects.toThrow('Network error');
  });
});
