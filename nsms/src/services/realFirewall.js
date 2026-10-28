// src/services/realFirewall.js
// Real OS-level firewall management (Windows netsh + Linux iptables)
const { exec } = require('child_process');
const os = require('os');

const platform = os.platform(); // 'win32' or 'linux'

/**
 * Add a real firewall block rule at the OS level.
 */
async function addFirewallRule({ sourceIp, targetIp, rule, ttlHours, ruleId }) {
  const ruleName = `NSMS_BLOCK_${ruleId.substring(0, 8)}`;

  if (platform === 'win32') {
    // Windows: netsh advfirewall
    const cmd = `netsh advfirewall firewall add rule name="${ruleName}" dir=in action=block remoteip=${sourceIp} enable=yes`;
    return execCommand(cmd, ruleName);
  } else {
    // Linux: iptables
    const cmd = `iptables -A INPUT -s ${sourceIp} -j DROP -m comment --comment "${ruleName}"`;
    return execCommand(cmd, ruleName);
  }
}

/**
 * Remove a firewall rule by its NSMS rule ID.
 */
async function removeFirewallRule(ruleId) {
  const ruleName = `NSMS_BLOCK_${ruleId.substring(0, 8)}`;

  if (platform === 'win32') {
    const cmd = `netsh advfirewall firewall delete rule name="${ruleName}"`;
    return execCommand(cmd, ruleName);
  } else {
    // Linux: find and delete the rule by comment
    const cmd = `iptables -D INPUT -m comment --comment "${ruleName}" -j DROP 2>/dev/null || true`;
    return execCommand(cmd, ruleName);
  }
}

function execCommand(cmd, label) {
  return new Promise((resolve) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        const combined = `${error.message || ''} ${stderr || ''} ${stdout || ''}`.toLowerCase();
        const isElevation = combined.includes('elevation') || combined.includes('privilege') || combined.includes('administrator') || error.code === 1;
        const isNotFound = combined.includes('no rules match');
        if (isElevation) {
          console.log(`[Firewall Info] ${label}: OS firewall requires admin rights. Enforced via in-memory WAF.`);
        } else if (!isNotFound) {
          console.error(`[Firewall] Error (${label}):`, error.message);
        }
        resolve({ success: false, error: error.message });
      } else {
        console.log(`[Firewall] Success (${label}):`, stdout.trim() || 'OK');
        resolve({ success: true, output: stdout.trim() });
      }
    });
  });
}

module.exports = { addFirewallRule, removeFirewallRule };
