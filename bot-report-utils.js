
function BotReportUtils(hasher, decoder) {
  this.hasher = hasher
  this.decoder = decoder

  this.extractFindingsJson = extractFindingsJson
  this.generateRubric = generateRubric
  this.makeRubricHash = makeRubricHash
}

async function generateRubric(salt, findings, aliases) {
  const aliasData = new Map()
  aliases.forEach(aliasGroup => {
    aliasGroup.forEach(alias => {
      aliasData.set(alias, aliasGroup)
    })
  })

  const hashes = []
  const classes = ['H','M','L','N','R','G','D']
  for (const finding of findings) {
    if (!finding.munged.ruleNum || !finding.munged.classDisplay) {
      continue
    }
    const numStr = `${finding.munged.ruleNum}`.padStart(2, '0')
    const label = `${finding.munged.classDisplay.toUpperCase()}‑${numStr}_dup`
    let titles = aliasData.get(finding.title)
    if (!titles) {
      titles = [finding.title]
    }
    for (const title of titles) {
      for (const clazz of classes) {
	// in the future we'll include individual instances, but for now
	// just operate on classes
	const hash = await this.makeRubricHash(clazz, salt, title, label)
	hashes.push(hash)
      }
    }
  }
  return {'salt': salt, 'hashes': hashes}
}

async function makeRubricHash(clss, salt, heading, label) {
  const entry = {'class': sanitizeStr(clss),
		 'salt': salt,
		 'title': sanitizeStr(heading),
		 'label': label
		}
  const eSorted = {};
  Object.keys(entry).sort().forEach((key) => {
    eSorted[key] = entry[key];
  });

  let hash = await this.hasher(JSON.stringify(eSorted))
  hash = hash.substr(0, 10)
  //console.log(`${hash} - ${JSON.stringify(eSorted)}`)
  return hash
}

function extractFindingsJson(reportBody, botName) {
  const result = []
  const reportBodyBlocks = reportBody.split(/(?:^|\n)#+[ \u00A0]+(?=[^\n]*[0-9]+)/g)
  reportBodyBlocks.forEach(block => {
    let heading = this.decoder(block.split('\n')[0].replaceAll(/<\/?[^`>]+(>|$)/g, '').trim())
    if ('' === heading) {
      return
    }
    const firstSpaceIndex = heading.search(/[\s\u00A0]/g)
    const label = heading.substr(0, firstSpaceIndex).trim()
    if (!/[0-9]/.test(label)) {
      return
    }
    const title = heading.substr(firstSpaceIndex).trim()
    const munged = mungeLabelAndTitle(label, title)

    const instances = []
    const urlRegex = /(https?:\/\/[^\s\)]+)/gi
    let match
    while ((match = urlRegex.exec(block)) !== null) {
      const url = match[1]
      match = url.match(/\/([^/]+\.sol)(?:#L(\d+)(?:-L(\d+))?)?/i)
      if (null === match) {
        continue
      }
      const file = match[1]
      const lineFrom = match[2] ? parseInt(match[2]) : null
      const lineTo = match[3] ? parseInt(match[3]) : null
      const instance = {'url':url, 'file':file, 'lineFrom':lineFrom, 'lineTo':lineTo}
      instances.push(instance)
    }

    const findingsGroup = {'label':label, 'title':title, 'munged':munged, 'instances':instances, 'botName':botName}
    result.push(findingsGroup)
  })
  return result
}

function labelToRuleClass(label) {
  if (!label) {
    return null
  }
  return label.toUpperCase().replaceAll(/[^HMLNRGDI]/g, '').trim().charAt(0)
}

function labelToNumber(label) {
  if (!label) {
    return null
  }
  return label.replaceAll(/[^0-9]/g, '').replaceAll(/^0+/g, '').trim()
}

function labelToDisplayLabel(label) {
  if (!label) {
    return null
  }
  const ruleClass = labelToRuleClass(label)
  const number = labelToNumber(label)
  if (!ruleClass || !number || '' === ruleClass || '' === number) {
    return null
  }
  return ruleClass + '-' + number
}

function sanitizeStr(str) {
  if (!str) {
    return str
  }
  //return str.toLowerCase().replaceAll(/[\s\u00A0]+/g,' ').replaceAll(/[^a-z0-9\.\_\/: \-\)\(\[\]#]/g, '').trim()
  return str.toLowerCase().replaceAll(/[\s\u00A0]+/g,' ').replaceAll(/`/g, '').replaceAll(/[^a-z0-9 ]/g, ' ').replaceAll(/\s+/g, ' ').trim()
}

function mungeLabelAndTitle(label, title) {
  const number = labelToNumber(label)
  const ruleClass = labelToRuleClass(label)
  const ruleClassSanitized = sanitizeStr(ruleClass)
  const displayLabel = labelToDisplayLabel(label)
  const titleSanitized = sanitizeStr(title)
  const result = {'ruleNum':number ? parseInt(number) : null, 'classDisplay':ruleClass, 'classSanitized':ruleClassSanitized, 
                  'labelDisplay':displayLabel, 'titleSanitized':titleSanitized}
  return result
}

function mungeLabelTitleAndScore(label, title, score) {
  const result = mungeLabelAndTitle(label, title, score)
  const scoreDisplay = score ? score : ''
  const scoreRuleClass = labelToRuleClass(score)
  let scoreCleaned = scoreDisplay !== '' ? scoreRuleClass : '_'
  if ('' == scoreCleaned) {
    scoreCleaned = '?'
  }
  if (/^(-[0-9]+|X|FALSE)$/.test(scoreDisplay.toUpperCase())) {
    scoreCleaned = 'D'
  }
  result.scoreDisplay = scoreDisplay
  result.scoreCleaned = scoreCleaned
  return result
}


// Export functions based on the environment
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  // This code will run in Node.js

  const cheerio = require('cheerio')
  function decodeHtmlEntities(encodedString) {
    const node = cheerio.load(encodedString, 
			      { xml: true, decodeEntities: false }, false);
    return node.html({ decodeEntities: false })
  }
  
  const crypto = require('crypto');
  async function hashStr(str) {
    return crypto.createHash('sha256').update(str).digest('hex')
  }

  function getBotReportUtils() {
    return new BotReportUtils(hashStr, decodeHtmlEntities)
  }

  module.exports.getBotReportUtils = getBotReportUtils
} else {
  // This code will run in the browser

  function decodeHtmlEntities(encodedString) {
    const tempElement = document.createElement('textarea')
    tempElement.innerHTML = encodedString
    return tempElement.value
  }

  async function hashStr(str) {
    const encoder = new TextEncoder()
    const dataBuffer = encoder.encode(str)
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('')
    const partialHash = hashHex.substr(0, 10)
    return partialHash
  }

  function getBotReportUtils() {
    return new BotReportUtils(hashStr, decodeHtmlEntities)
  }
}

/**
// Example rubric generation in node.js
const bru = require('./bot-report-utils.js').getBotReportUtils()
const body = require('fs').readFileSync("/tmp/report.md", 'utf8')
const findings = bru.extractFindingsJson(body, 'MyBotName')
console.log(JSON.stringify(findings, null, 2))
bru.generateRubric("salt123", findings, []).then(r => {
  console.log(JSON.stringify(r))
})
/**/
