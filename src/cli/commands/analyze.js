// src/cli/commands/analyze.js

const Analyzer = require('../../core/analyzer');
const chalk = require('chalk');
const ora = require('ora');
const Table = require('cli-table3');
const { 
  formatScore, 
  formatMetricValue, 
  formatMetricName, 
  generateRecommendations 
} = require('../formatters');

const EXIT_CODES = {
  SUCCESS: 0,
  SECURITY_FAIL: 1,
  CONFIG_ERROR: 2,
  NETWORK_ERROR: 3
};

module.exports = async (packageName, options) => {
  const spinner = ora({
    text: `Analyzing ${packageName}...`,
    color: 'blue'
  }).start();

  try {
    const analyzer = new Analyzer();
    const results = await analyzer.analyzePackage(packageName, options.version);
    spinner.stop();

    if (options.scoreOnly) {
      console.log(`\nSecurity Score: ${formatScore(results.score)}`);
      return;
    }

    // Display Summary
    displaySummary(results);

    // Display Security Analysis
    displaySecurityAnalysis(results);
    
    // Display detailed analysis if requested
    if (options.detailed) {
      displayDetailedAnalysis(results);
    }

    // Display recommendations
    displayRecommendations(results);

  } catch (error) {
    spinner.fail(chalk.red('Analysis failed'));
    
    if (error.code === 'ENOENT' || error.code === 'ENOTFOUND') {
      console.error(chalk.red('\nNetwork Error:', error.message));
      process.exit(EXIT_CODES.NETWORK_ERROR);
    } else if (error.message.includes('config')) {
      console.error(chalk.red('\nConfiguration Error:', error.message));
      process.exit(EXIT_CODES.CONFIG_ERROR);
    } else {
      console.error(chalk.red('\nSecurity Check Failed:', error.message));
      process.exit(EXIT_CODES.SECURITY_FAIL);
    }
  }
};

// Formatting helpers
function formatNumber(num) {
  return new Intl.NumberFormat().format(num);
}

function formatDate(dateStr) {
  if (!dateStr) return 'Unknown';
  return new Date(dateStr).toLocaleDateString();
}

// Display functions
function displaySummary(results) {
  console.log('\n📊 Package Analysis Summary');
  console.log('─'.repeat(50));
  
  const table = new Table({
    head: ['Metric', 'Value'].map(h => chalk.cyan ? chalk.cyan(h) : h)
  });

  table.push(
    ['Package', results.basicInfo.name],
    ['Version', results.basicInfo.version],
    ['Security Score', formatScore(results.score)],
    ['Author', results.basicInfo.author?.name || 'Unknown'],
    ['License', results.basicInfo.license || 'Not specified']
  );

  console.log(table.toString());
}

function displaySecurityAnalysis(results) {
  console.log('\n🛡️  Security Analysis');
  console.log('─'.repeat(50));

  const vulns = results.vulnerabilities || {};
  console.log(`Critical: ${chalk.red(vulns.critical?.length || 0)}`);
  console.log(`High: ${chalk.yellow(vulns.high?.length || 0)}`);
  console.log(`Moderate: ${chalk.blue(vulns.moderate?.length || 0)}`);
  console.log(`Network Security: ${formatMetricValue(results.securityMetrics?.networkSecurity)}`);
}

function displayDetailedAnalysis(results) {
  console.log('\n🔍 Detailed Analysis');
  console.log('─'.repeat(50));

  // Dependencies section
  console.log('\nDependencies:');
  if (results.dependencies) {
    Object.entries(results.dependencies).forEach(([name, version]) => {
      console.log(`- ${name}@${typeof version === 'string' ? version : version.version}`);
    });
  }

  // Security Metrics section
  console.log('\nSecurity Metrics:');
  if (results.securityMetrics) {
    Object.entries(results.securityMetrics).forEach(([key, value]) => {
      console.log(`${formatMetricName(key)}: ${formatMetricValue(value)}`);
    });
  }

  // Vulnerabilities section
  console.log('\nVulnerabilities:');
  if (results.vulnerabilities?.critical?.length) {
    results.vulnerabilities.critical.forEach(cve => {
      console.log(`- Critical: ${cve}`);
    });
  }
}

module.exports = {
  formatScore,
  formatMetricValue,
  generateRecommendations,
  displaySummary,
  displaySecurityAnalysis,
  displayDetailedAnalysis
};
*/