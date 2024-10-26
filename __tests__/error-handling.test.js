const axios = require('axios');
const Scanner = require('../src/core/scanner');

jest.mock('axios');

describe('Error Handling', () => {
  let scanner;

  beforeEach(() => {
    scanner = new Scanner();
    jest.clearAllMocks();
  });

  test('handles malformed package data', async () => {
    const malformedData = { data: {} };
    axios.get.mockResolvedValue(malformedData);

    await expect(scanner.scanPackage('bad-pkg'))
      .rejects.toThrow('Invalid package data');
  });

  test('handles network timeouts', async () => {
    const timeoutError = new Error('ETIMEDOUT');
    axios.get.mockRejectedValue(timeoutError);

    await expect(scanner.scanPackage('timeout-pkg'))
    .rejects.toThrow('Failed to analyze package: ETIMEDOUT');

  });

  test('handles rate limiting', async () => {
    const rateLimitError = new Error('429 Too Many Requests');
    axios.get.mockRejectedValue(rateLimitError);

    await expect(scanner.scanPackage('limited-pkg'))
    .rejects.toThrow('Failed to analyze package: 429 Too Many Requests');

  });

  test('handles invalid configurations', async () => {
    process.env.npm_package_config_guardpkg = 'invalid-json';
    
    await expect(scanner.shouldBlockInstallation({ score: 50 }))
      .rejects.toThrow('Invalid configuration');
  });
});
