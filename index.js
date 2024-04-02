#!/usr/bin/env node

async function readAudit() {
  const chunks = []
  const stdin = process.stdin

  stdin.resume()
  stdin.setEncoding('utf-8')
  stdin.on('data', (chunk) => {
    chunks.push(chunk)
  })

  return new Promise((resolve, reject) => {
    stdin.on('end', () => {
      resolve(JSON.parse(chunks.join('')))
    });
    stdin.on('error', () => {
      reject(Error('error during read'))
    })
    stdin.on('timeout', () => {
      reject(Error('timout during read'))
    })
  })
}


const severities = {
  info: 'LOW',
  low: 'LOW',
  moderate: 'MEDIUM',
  high: 'MEDIUM',
  critical: 'HIGH',
};


async function main() {
  const pnpmAudit = await readAudit()
  const rules = []
  const issues = []
  for (const advice of Object.values(pnpmAudit.advisories || [])) {
    rules.push({
      id: `${advice.id}`,
      name: advice.github_advisory_id || advice.npm_advisory_id || `rule_${advice.id}`,
      description: `<h1>${advice.module_name} ${advice.vulnerable_versions}</h1>
<h2>${advice.title || ''}</h2>

Overview:
<pre>
${advice.overview || ''}
</pre>

References:
<pre>
${advice.references || ''}
</pre>
`,
      cleanCodeAttribute: "TRUSTWORTHY",
      engineId: "pnpm-audit",
      impacts: [{
        softwareQuality: "SECURITY",
        severity: severities[advice.severity],
      }]
    })
    issues.push({
      ruleId: `${advice.id}`,
      efforMinutes: 0,
      primaryLocation: {
        message: advice.title,
        filePath: "pnpm-lock.yaml",
      },
      secondaryLocations: []
    })
  }
  console.log(JSON.stringify({ rules, issues }, null, 2))
}

main()