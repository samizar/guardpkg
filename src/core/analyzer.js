const Scanner = require('./scanner');
const Detector = require('./detector');

class Analyzer {
  constructor() {
    this.scanner = new Scanner();
    this.detector = new Detector();
  }

  async analyzePackage(packageName, version = 'latest') {
    try {
      // Get package metadata and scan results
      const scanResults = await this.scanner.scanPackage(packageName, version);
      
      // Validate scan results
      if (!scanResults || !scanResults.basicInfo) {
        throw new Error('Invalid scan results');
      }
      
      // Run security analysis
      const detectionResults = await this.detector.analyzeTarball(packageName, version);
      
      return {
        basicInfo: scanResults.basicInfo,
        score: scanResults.score || this.calculateSecurityScore({
          ...scanResults,
          ...detectionResults
        }),
        risks: detectionResults.risks || [],
        vulnerabilities: scanResults.vulnerabilities || {},
        dependencies: scanResults.dependencies || {},
        securityMetrics: scanResults.securityMetrics || {},
        suspiciousPatterns: detectionResults.suspiciousPatterns || [],
        malwareDetected: detectionResults.malwareDetected || false
      };
    } catch (error) {
      // Pass through network errors directly
      if (error.message.includes('Network error')) {
        throw error;
      }
      throw new Error(`Failed to analyze package: ${error.message}`);
    }
  }

  calculateSecurityScore(results) {
    let score = 100;
    score -= (results.risks?.length || 0) * 15;
    score -= (results.vulnerabilities?.critical?.length || 0) * 20;
    score -= (results.vulnerabilities?.high?.length || 0) * 10;
    score -= (results.suspiciousPatterns?.length || 0) * 5;
    return Math.max(0, Math.min(100, score));
  }
}

module.exports = Analyzer;
