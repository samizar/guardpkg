const chalk = require('chalk');

function formatScore(score) {
  return chalk.bold(
    score >= 80 ? chalk.green(`${score}/100`) :
    score >= 50 ? chalk.yellow(`${score}/100`) :
    chalk.red(`${score}/100`)
  );
}

function formatMetricValue(value) {
  if (value === null || value === undefined) return 'N/A';
  if (typeof value === 'boolean') return value ? chalk.green('Yes') : chalk.red('No');
  return value;
}

function formatMetricName(name) {
  return name.replace(/([A-Z])/g, ' $1')
    .replace(/^./, str => str.toUpperCase())
    .trim();
}

function generateRecommendations(results) {
  const recs = [];

  if (results.score < 80) {
    if (results.vulnerabilities?.critical?.length > 0) {
      recs.push({
        title: 'Critical Vulnerabilities',
        description: 'Critical security vulnerabilities detected. Strongly recommend finding alternative package.'
      });
    }

    if (results.securityMetrics?.hasSuspiciousScripts) {
      recs.push({
        title: 'Suspicious Scripts',
        description: 'Package contains potentially dangerous npm scripts. Review them carefully.'
      });
    }

    if (!results.securityMetrics?.hasLockFile) {
      recs.push({
        title: 'Missing Lock File',
        description: 'Package lacks a lock file. Dependencies may be unstable.'
      });
    }
  }

  return recs;
}

module.exports = {
  formatScore,
  formatMetricValue,
  formatMetricName,
  generateRecommendations
};
