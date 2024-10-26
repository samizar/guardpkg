module.exports = {
  npmRegistry: 'https://registry.npmjs.org',
  scoreThresholds: {
    high: 80,
    medium: 50,
    low: 30
  },
  maxDepth: 10,
  tempDir: '.temp-analysis',
  fileExtensions: ['.js', '.json', '.ts', '.jsx', '.tsx']
};
