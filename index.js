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
  info: 'INFO',
  low: 'MINOR',
  moderate: 'MINOR',
  high: 'CRITICAL',
  critical: 'BLOCKER',
};


async function main() {
  const pnpmAudit = await readAudit()
  const issues = []
  for (const advice of Object.values(pnpmAudit.advisories || [])) {
    issues.push({
      "engineId": "pnpm-audit",
      "ruleId": advice.id,
      "severity": severities[advice.severity],
      "type": "VULNERABILITY",
      "efforMinutes": 0,
      "primaryLocation": {
        "message": `${advice.module_name} ${advice.vulnerable_versions}
${advice.title || ''}

Overview:
${advice.overview || ''}

References:
${advice.references || ''}
`,
        "filePath": "pnpm-lock.yaml",
      },
      "secondaryLocations": []
    })
  }
  console.log(JSON.stringify({ issues }, null, 2))
}

main()