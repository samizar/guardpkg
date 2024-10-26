const chalk = require('chalk');
const Table = require('cli-table3');
const { 
  formatScore, 
  formatMetricValue, 
  formatMetricName, 
  generateRecommendations 
} = require('../formatters');

function displaySummary(results) {
  console.log('\n📊 Package Analysis Summary');
  console.log('─'.repeat(50));
  
  const table = new Table({
    head: ['Metric', 'Value'].map(h => chalk.cyan(h))
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

  console.log('\nDependencies:');
  if (results.dependencies) {
    Object.entries(results.dependencies).forEach(([name, version]) => {
      console.log(`- ${name}@${typeof version === 'string' ? version : version.version}`);
    });
  }

  console.log('\nSecurity Metrics:');
  if (results.securityMetrics) {
    Object.entries(results.securityMetrics).forEach(([key, value]) => {
      console.log(`${formatMetricName(key)}: ${formatMetricValue(value)}`);
    });
  }
}

function displayRecommendations(results) {
  console.log('\n💡 Recommendations');
  console.log('─'.repeat(50));

  const recommendations = generateRecommendations(results);
  if (recommendations.length === 0) {
    console.log('\n✅ No security concerns found for this package.');
    return;
  }

  recommendations.forEach(rec => {
    console.log(`\n${chalk.bold(rec.title)}`);
    console.log(rec.description);
  });
}

module.exports = {
  displaySummary,
  displaySecurityAnalysis,
  displayDetailedAnalysis,
  displayRecommendations
};
