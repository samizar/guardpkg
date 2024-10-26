#!/usr/bin/env node
const analyzer = require('../core/analyzer');
const chalk = require('chalk');
const ora = require('ora');

const EXIT_CODES = {
  SUCCESS: 0,
  SECURITY_FAIL: 1,
  CONFIG_ERROR: 2,
  NETWORK_ERROR: 3
};

async function preinstallHook() {
  try {
    const npmArgs = JSON.parse(process.env.npm_config_argv || '{"remain":[], "original":[]}');
    const packageToInstall = npmArgs.remain[0];
    const isForceInstall = npmArgs.original.includes('--force');

    if (!packageToInstall) return;
    if (isForceInstall) {
      console.log(chalk.yellow('⚠️  Force install detected - bypassing security checks'));
      return;
    }

    const spinner = ora({
      text: `🔍 GuardPkg: Analyzing ${packageToInstall} before installation...`,
      color: 'blue'
    }).start();

    const results = await analyzer.analyzePackage(packageToInstall);
    spinner.stop();

    if (results.score < 50) {
      console.log(chalk.red(`
⚠️  Security Warning for ${packageToInstall}
────────────────────────────────────
• Security Score: ${results.score}/100
• ${results.risks.join('\n• ')}

To install anyway, use: npm install ${packageToInstall} --force
      `));
      process.exit(EXIT_CODES.SECURITY_FAIL);
    }

    console.log(chalk.green(`✅ ${packageToInstall} passed security check (Score: ${results.score}/100)`));
    process.exit(EXIT_CODES.SUCCESS);
  } catch (error) {
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
}

preinstallHook();
