exports.isKnownGoodDomain = (url) => {
  const trustedDomains = [
    'registry.npmjs.org',
    'github.com',
    'githubusercontent.com',
    'unpkg.com',
    'cdnjs.cloudflare.com'
  ];
  
  try {
    const domain = new URL(url).hostname;
    return trustedDomains.some(trusted => domain.endsWith(trusted));
  } catch {
    return false;
  }
};
