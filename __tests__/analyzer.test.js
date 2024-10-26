// Place mocks at the very top
jest.mock('../src/core/scanner');
jest.mock('../src/core/detector');

const Analyzer = require('../src/core/analyzer');
const Scanner = require('../src/core/scanner');
const Detector = require('../src/core/detector');

describe('Package Analyzer', () => {
  let analyzer;

  beforeEach(() => {
    jest.clearAllMocks();
    analyzer = new Analyzer();
  });

  test('analyzePackage returns valid results', async () => {
    const mockScanResults = {
      score: 85,
      basicInfo: {
        name: 'test-package',
        version: '1.0.0'
      }
    };

    // Mock both required methods
    Scanner.prototype.scanPackage.mockResolvedValue(mockScanResults);
    Detector.prototype.analyzeTarball.mockResolvedValue({
      malwareDetected: false,
      suspiciousPatterns: [],
      risks: [],
      score: 85
    });

    const results = await analyzer.analyzePackage('test-package');
    expect(results).toBeDefined();
    expect(results.score).toBe(85);
    expect(results.basicInfo.name).toBe('test-package');
  });

  test('handles network errors', async () => {
    const networkError = new Error('Network error');
    // Both methods should reject
    Scanner.prototype.scanPackage.mockRejectedValue(networkError);
    Detector.prototype.analyzeTarball.mockRejectedValue(networkError);

    await expect(analyzer.analyzePackage('test-package')).rejects.toThrow('Network error');
  });

  describe('error handling', () => {
    test('handles invalid package names', async () => {
      Scanner.prototype.scanPackage.mockRejectedValue(
        new Error('Invalid package name')
      );

      await expect(analyzer.analyzePackage('@@invalid@@'))
        .rejects.toThrow('Failed to analyze package: Invalid package name');
    });

    test('handles scan failures gracefully', async () => {
      Scanner.prototype.scanPackage.mockRejectedValue(
        new Error('Scan failed')
      );
      Detector.prototype.analyzeTarball.mockResolvedValue({
        malwareDetected: false,
        suspiciousPatterns: [],
        risks: [],
        score: 85
      });

      await expect(analyzer.analyzePackage('test-package'))
        .rejects.toThrow('Failed to analyze package: Scan failed');
    });

    test('handles malformed scan results', async () => {
      Scanner.prototype.scanPackage.mockResolvedValue({
        // Missing required fields
      });

      await expect(analyzer.analyzePackage('test-package'))
        .rejects.toThrow('Failed to analyze package: Invalid scan results');
    });
  });
});
