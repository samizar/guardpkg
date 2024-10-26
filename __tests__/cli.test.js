const chalk = require('chalk');
const { 
  displaySummary,
  displaySecurityAnalysis,
  displayDetailedAnalysis
} = require('../src/cli/commands/display');
const {
  formatScore,
  formatMetricValue,
  generateRecommendations
} = require('../src/cli/formatters');

// Mock external dependencies
jest.mock('chalk', () => ({
  green: jest.fn(text => `green:${text}`),
  yellow: jest.fn(text => `yellow:${text}`),
  red: jest.fn(text => `red:${text}`),
  blue: jest.fn(text => `blue:${text}`),
  cyan: jest.fn(text => `cyan:${text}`),
  bold: jest.fn(text => `bold:${text}`)
}));

jest.mock('ora', () => () => ({
  start: jest.fn().mockReturnThis(),
  stop: jest.fn().mockReturnThis(),
  succeed: jest.fn().mockReturnThis(),
  fail: jest.fn().mockReturnThis()
}));

jest.mock('cli-table3', () => 
  jest.fn().mockImplementation(() => ({
    push: jest.fn(),
    toString: jest.fn().mockReturnValue('test-package\nTest Author')
  }))
);

describe('CLI Formatting', () => {
  test('formatScore uses correct colors', () => {
    expect(formatScore(90)).toContain('green');
    expect(formatScore(70)).toContain('yellow');
    expect(formatScore(40)).toContain('red');
  });

  test('formatMetricValue handles different types', () => {
    expect(formatMetricValue(true)).toContain('Yes');
    expect(formatMetricValue(false)).toContain('No');
    expect(formatMetricValue(42)).toBe(42);
  });

  test('generateRecommendations includes critical issues', () => {
    const results = {
      score: 30,
      vulnerabilities: {
        critical: ['CVE-2023-1234']
      },
      securityMetrics: {
        hasSuspiciousScripts: true,
        hasLockFile: false
      }
    };
    
    const recs = generateRecommendations(results);
    expect(recs).toHaveLength(3);
    expect(recs[0].title).toBe('Critical Vulnerabilities');
  });
});

describe('CLI Display Functions', () => {
  let consoleLogSpy;
  
  beforeEach(() => {
    consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
  });

  test('displaySummary shows all package information', () => {
    const results = {
      basicInfo: {
        name: 'test-package',
        version: '1.0.0',
        author: { name: 'Test Author' },
        downloads: 1000,
        lastPublished: '2023-01-01',
        license: 'MIT'
      },
      score: 85
    };

    displaySummary(results);
    expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('test-package'));
    expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('Test Author'));
  });

  test('displaySecurityAnalysis shows all security information', () => {
    const results = {
      risks: ['Critical vulnerability found'],
      suspiciousPatterns: [
        { category: 'Network', pattern: 'eval()', snippet: 'eval("malicious")' }
      ],
      vulnerabilities: {
        critical: ['CVE-1'],
        high: ['CVE-2'],
        moderate: ['CVE-3'],
        low: ['CVE-4']
      }
    };

    displaySecurityAnalysis(results);
    expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('Critical'));
    expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('Network'));
  });

  test('displayDetailedAnalysis shows complete analysis', () => {
    const results = {
      dependencies: {
        'dep1': {
          version: '1.0.0',
          latest: '1.1.0',
          type: 'production',
          securityScore: 85
        }
      },
      securityMetrics: {
        hasSuspiciousScripts: false,
        hasLockFile: true
      },
      publisherInfo: {
        name: 'trusted-publisher',
        isVerified: true
      }
    };

    displayDetailedAnalysis(results);
    expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('dep1'));
    expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('Security Metrics'));
  });
});

describe('CLI Functions', () => {
  describe('display functions', () => {
    let consoleLogSpy;
    
    beforeEach(() => {
      consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
    });

    afterEach(() => {
      consoleLogSpy.mockRestore();
    });

    test('displayDetailedAnalysis shows all sections', () => {
      const results = {
        basicInfo: {
          name: 'test-pkg',
          version: '1.0.0',
          author: 'Test Author'
        },
        vulnerabilities: {
          critical: ['CVE-1'],
          high: ['CVE-2']
        },
        securityMetrics: {
          hasSuspiciousScripts: true,
          hasLockFile: false
        },
        dependencies: {
          'dep1': '1.0.0',
          'dep2': '2.0.0'
        }
      };

      displayDetailedAnalysis(results);
      expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('Detailed Analysis'));
      expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('CVE-1'));
      expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('dep1'));
    });

    test('formatMetricValue handles all value types', () => {
      expect(formatMetricValue(true)).toContain('Yes');
      expect(formatMetricValue(false)).toContain('No');
      expect(formatMetricValue(42)).toBe(42);
      expect(formatMetricValue('string')).toBe('string');
      expect(formatMetricValue(null)).toBe('N/A');
      expect(formatMetricValue(undefined)).toBe('N/A');
    });
  });
});
