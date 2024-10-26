const Analyzer = require('../../core/analyzer');
const chalk = require('chalk');
const ora = require('ora');
const { 
  formatScore,
  generateRecommendations
} = require('../formatters');
const {
  displaySummary,
  displaySecurityAnalysis,
  displayDetailedAnalysis,
  displayRecommendations
} = require('./display');

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

    displaySummary(results);
    displaySecurityAnalysis(results);
    
    if (options.detailed) {
      displayDetailedAnalysis(results);
    }

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
