#!/usr/bin/env node

const { program } = require('commander');
const analyzeCommand = require('./commands/analyze-command');
const pkg = require('../../package.json');

program
  .version(pkg.version)
  .description('GuardPkg - Your NPM Package Guardian');

// Define analyze as a subcommand
program
  .command('analyze <package>')
  .description('Analyze an npm package for security vulnerabilities')
  .option('-d, --detailed', 'show detailed analysis')
  .option('-s, --score-only', 'show only the security score')
  .option('-v, --version <version>', 'package version to analyze', 'latest')
  .action(analyzeCommand);

program
  .command('config')
  .description('Configure GuardPkg settings')
  .option('--auto-check <boolean>', 'enable/disable automatic checking')
  .option('--score-threshold <number>', 'set minimum security score')
  .option('--block-install <boolean>', 'block installation of suspicious packages')
  .action(require('./commands/config'));

program.parse(process.argv);
