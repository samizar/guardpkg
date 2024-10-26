const chalk = require('chalk');
const { execSync } = require('child_process');
const EXIT_CODES = require('../constants/exitCodes');

function validateConfig(options) {
  if (options.scoreThreshold !== undefined) {
    const score = parseInt(options.scoreThreshold);
    if (isNaN(score) || score < 0 || score > 100) {
      throw new Error('Score threshold must be a number between 0 and 100');
    }
  }

  if (options.autoCheck !== undefined) {
    if (!['true', 'false'].includes(options.autoCheck)) {
      throw new Error('Auto-check must be either "true" or "false"');
    }
  }

  if (options.blockInstall !== undefined) {
    if (!['true', 'false'].includes(options.blockInstall)) {
      throw new Error('Block-install must be either "true" or "false"');
    }
  }
}

module.exports = (options) => {
  try {
    validateConfig(options);

    const updates = [];

    if (options.autoCheck !== undefined) {
      execSync(`npm config set guardpkg:autoCheck ${options.autoCheck}`);
      updates.push(`Auto-check: ${options.autoCheck}`);
    }
    
    if (options.scoreThreshold !== undefined) {
      execSync(`npm config set guardpkg:scoreThreshold ${options.scoreThreshold}`);
      updates.push(`Score threshold: ${options.scoreThreshold}`);
    }
    
    if (options.blockInstall !== undefined) {
      execSync(`npm config set guardpkg:blockInstall ${options.blockInstall}`);
      updates.push(`Block install: ${options.blockInstall}`);
    }

    if (updates.length > 0) {
      console.log(chalk.green('\n✅ Configuration updated:'));
      updates.forEach(update => console.log(chalk.cyan(`• ${update}`)));
    } else {
      console.log(chalk.yellow('\nℹ️  No configuration changes made'));
    }
    
    process.exit(EXIT_CODES.SUCCESS);
  } catch (error) {
    console.error(chalk.red('\n❌ Configuration Error:', error.message));
    process.exit(EXIT_CODES.CONFIG_ERROR);
  }
};
