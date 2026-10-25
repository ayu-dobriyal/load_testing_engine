// src/services/firewallMock.js
/**
 * Mock service that pretends to apply a firewall rule.
 * In a real deployment this would call the firewall's API / CLI.
 */
async function addFirewallRule({ sourceIp, targetIp, rule, ttlHours }) {
  // For demonstration we just log the action.
  console.log('[Mock Firewall] Adding rule:', {
    sourceIp,
    targetIp,
    rule,
    ttlHours,
  });
  // Simulate async I/O latency
  await new Promise((resolve) => setTimeout(resolve, 50));
  // Return a mock identifier
  return { success: true, ruleId: `mock-${Date.now()}` };
}

module.exports = { addFirewallRule };
