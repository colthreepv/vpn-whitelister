import type { Socket } from 'bun'
import { Buffer } from 'node:buffer'
import { connect as bunConnect } from 'bun'
import {
  EXTERNAL_PORT,
  INTERNAL_PORT,
  IPTABLES_AGENT_HOST,
  IPTABLES_AGENT_PORT,
  IPTABLES_FILTER_CHAIN,
  IPTABLES_NAT_CHAIN,
} from './config'

// --- Core IPTables Command Execution ---

// Export for mocking in tests if tests are co-located or need direct access
export async function executeIPTablesCommand(args: string[]): Promise<{ success: boolean, stdout?: string, stderr?: string, exitCode?: number }> {
  const commandString = args.join(' ')
  console.warn(`Agent CMD: iptables ${commandString}`)

  return new Promise((resolve, reject) => {
    let clientSocket: Socket | undefined
    let rawOutput = ''
    let connectionOpened = false

    const timeoutHandle = setTimeout(() => {
      if (clientSocket) {
        clientSocket.end()
      }
      if (!connectionOpened || !rawOutput.includes('---END---')) {
        reject(new Error(`Agent response timeout for: iptables ${commandString}`))
      }
    }, 10000)

    ;(async () => {
      try {
        clientSocket = await bunConnect({
          hostname: IPTABLES_AGENT_HOST,
          port: IPTABLES_AGENT_PORT,
          socket: {
            data(currentSock, data) {
              rawOutput += Buffer.from(data).toString()
            },
            open(currentSock) {
              connectionOpened = true
              currentSock.write(`${commandString}\n`)
              currentSock.flush()
            },
            close(_currentSock) {
              clearTimeout(timeoutHandle)
              if (!connectionOpened) {
                reject(new Error(`Agent connection closed before opening or refused for: iptables ${commandString}`))
                return
              }
              if (rawOutput.includes('---END---')) {
                let exitCode = -1
                let stdout = ''
                let stderr = ''
                const lines = rawOutput.split(/\r?\n/)
                let currentSection: 'stdout' | 'stderr' | null = null

                for (const line of lines) {
                  if (line.startsWith('EXIT_CODE:')) {
                    exitCode = Number.parseInt(line.substring('EXIT_CODE:'.length), 10)
                  }
                  else if (line === '---STDOUT---') {
                    currentSection = 'stdout'
                  }
                  else if (line === '---STDERR---') {
                    currentSection = 'stderr'
                  }
                  else if (line === '---END---') {
                    currentSection = null
                    break
                  }
                  else if (currentSection === 'stdout') {
                    stdout += (stdout ? '\n' : '') + line
                  }
                  else if (currentSection === 'stderr') {
                    stderr += (stderr ? '\n' : '') + line
                  }
                }
                resolve(processAgentResponse(args, commandString, exitCode, stdout, stderr))
              }
              else {
                reject(new Error(`Agent response incomplete (missing ---END---) for: iptables ${commandString}. Received: ${rawOutput.substring(0, 200)}...`))
              }
            },
            error(currentSock, error) {
              clearTimeout(timeoutHandle)
              if (currentSock)
                currentSock.end()
              reject(new Error(`Agent socket error for 'iptables ${commandString}': ${error.message}`))
            },
          },
        })
      }
      catch (error: any) {
        clearTimeout(timeoutHandle)
        if (clientSocket) {
          clientSocket.end()
        }
        console.error(`Error during agent connection setup for 'iptables ${commandString}': ${error.message}`)
        reject(new Error(`Agent connection setup error for 'iptables ${commandString}': ${error.message}`))
      }
    })()
  })
}

function processAgentResponse(
  args: string[],
  commandString: string,
  exitCode: number,
  stdout: string,
  stderr: string,
): { success: boolean, stdout?: string, stderr?: string, exitCode?: number } {
  const operationFlag = args.find(arg => ['-A', '-D', '-C', '-N', '-X', '-F', '-L', '-S', '-I'].includes(arg))
  const ruleNotFoundMessages = [
    'no chain/target/match by that name',
    'bad rule',
    'rule is not in chain',
    'does not exist',
    'target by that name not found',
    'is not a chain',
  ]

  const effectiveStdout = stdout.trim()
  const effectiveStderr = stderr.trim()
  const combinedOutputLower = (effectiveStdout + effectiveStderr).toLowerCase()
  const outputIndicatesRuleNotFound = ruleNotFoundMessages.some(msg => combinedOutputLower.includes(msg))

  if (effectiveStdout) {
    console.warn(`Agent STDOUT: ${effectiveStdout}`)
  }

  if (effectiveStderr) {
    const isExpectedRuleNotFoundForDeleteOrCheck
            = (operationFlag === '-D' || operationFlag === '-C') && outputIndicatesRuleNotFound
    const isChainAlreadyExistsForCreate
            = operationFlag === '-N' && combinedOutputLower.includes('chain already exists')
    const isChainNotFoundForDelete
            = operationFlag === '-X' && outputIndicatesRuleNotFound

    if (!(isExpectedRuleNotFoundForDeleteOrCheck || isChainAlreadyExistsForCreate || isChainNotFoundForDelete)) {
      console.warn(`Agent STDERR: ${effectiveStderr}`)
    }
  }

  if (exitCode === 0) {
    return { success: true, stdout: effectiveStdout, stderr: effectiveStderr, exitCode }
  }
  else {
    if (operationFlag === '-N' && (combinedOutputLower.includes('chain already exists'))) {
      console.warn(`Agent: Chain creation reported 'Chain already exists' (considered success for -N): iptables ${commandString}. Exit: ${exitCode}`)
      return { success: true, stdout: effectiveStdout, stderr: effectiveStderr, exitCode: 0 }
    }
    if ((operationFlag === '-D' || operationFlag === '-X') && outputIndicatesRuleNotFound) {
      console.warn(`Agent: Attempted to remove/delete non-existent rule/chain (considered success for ${operationFlag}): iptables ${commandString}. Exit: ${exitCode}`)
      return { success: true, stdout: effectiveStdout, stderr: effectiveStderr, exitCode }
    }
    if (operationFlag === '-C' && outputIndicatesRuleNotFound) {
      console.warn(`Agent: Rule check reported 'rule does not exist' (expected for -C, returning success:false): iptables ${commandString}. Exit: ${exitCode}`)
      return { success: false, stdout: effectiveStdout, stderr: effectiveStderr, exitCode }
    }
    console.error(`Agent CMD FAIL: iptables ${commandString} exited with ${exitCode}. Stderr: ${effectiveStderr} Stdout: ${effectiveStdout}`)
    return { success: false, stdout: effectiveStdout, stderr: effectiveStderr, exitCode }
  }
}

// --- Chain Management ---

export async function initializeChains(): Promise<void> {
  console.warn('Initializing custom iptables chains...')
  let result = await executeIPTablesCommand(['-t', 'nat', '-N', IPTABLES_NAT_CHAIN])
  if (!result.success) {
    console.error(`Failed to create NAT chain ${IPTABLES_NAT_CHAIN}. stderr: ${result.stderr}`)
  }
  result = await executeIPTablesCommand(['-t', 'nat', '-C', 'PREROUTING', '-j', IPTABLES_NAT_CHAIN])
  if (!result.success) {
    result = await executeIPTablesCommand(['-t', 'nat', '-A', 'PREROUTING', '-j', IPTABLES_NAT_CHAIN])
    if (!result.success) {
      console.error(`Failed to link NAT chain ${IPTABLES_NAT_CHAIN} to PREROUTING. stderr: ${result.stderr}`)
    }
  }
  else {
    console.warn(`Rule to jump from PREROUTING to ${IPTABLES_NAT_CHAIN} already exists.`)
  }
  result = await executeIPTablesCommand(['-N', IPTABLES_FILTER_CHAIN])
  if (!result.success) {
    console.error(`Failed to create filter chain ${IPTABLES_FILTER_CHAIN}. stderr: ${result.stderr}`)
  }
  result = await executeIPTablesCommand(['-C', 'INPUT', '-j', IPTABLES_FILTER_CHAIN])
  if (!result.success) {
    result = await executeIPTablesCommand(['-A', 'INPUT', '-j', IPTABLES_FILTER_CHAIN])
    if (!result.success) {
      console.error(`Failed to link filter chain ${IPTABLES_FILTER_CHAIN} to INPUT. stderr: ${result.stderr}`)
    }
  }
  else {
    console.warn(`Rule to jump from INPUT to ${IPTABLES_FILTER_CHAIN} already exists.`)
  }
  console.warn('Custom iptables chains initialization attempt complete.')
}

export async function cleanupChains(): Promise<void> {
  console.warn('Cleaning up custom iptables chains...')
  let result
  result = await executeIPTablesCommand(['-t', 'nat', '-C', 'PREROUTING', '-j', IPTABLES_NAT_CHAIN])
  if (result.success) {
    result = await executeIPTablesCommand(['-t', 'nat', '-D', 'PREROUTING', '-j', IPTABLES_NAT_CHAIN])
    if (!result.success) {
      console.error(`Failed to unlink NAT chain ${IPTABLES_NAT_CHAIN} from PREROUTING. stderr: ${result.stderr}`)
    }
  }
  else {
    console.warn(`Jump rule from PREROUTING to ${IPTABLES_NAT_CHAIN} does not exist or already removed.`)
  }
  result = await executeIPTablesCommand(['-t', 'nat', '-F', IPTABLES_NAT_CHAIN])
  if (!result.success) {
    console.error(`Failed to flush NAT chain ${IPTABLES_NAT_CHAIN}. stderr: ${result.stderr}`)
  }
  result = await executeIPTablesCommand(['-t', 'nat', '-X', IPTABLES_NAT_CHAIN])
  if (!result.success) {
    console.error(`Failed to delete NAT chain ${IPTABLES_NAT_CHAIN}. stderr: ${result.stderr}`)
  }
  result = await executeIPTablesCommand(['-C', 'INPUT', '-j', IPTABLES_FILTER_CHAIN])
  if (result.success) {
    result = await executeIPTablesCommand(['-D', 'INPUT', '-j', IPTABLES_FILTER_CHAIN])
    if (!result.success) {
      console.error(`Failed to unlink filter chain ${IPTABLES_FILTER_CHAIN} from INPUT. stderr: ${result.stderr}`)
    }
  }
  else {
    console.warn(`Jump rule from INPUT to ${IPTABLES_FILTER_CHAIN} does not exist or already removed.`)
  }
  result = await executeIPTablesCommand(['-F', IPTABLES_FILTER_CHAIN])
  if (!result.success) {
    console.error(`Failed to flush filter chain ${IPTABLES_FILTER_CHAIN}. stderr: ${result.stderr}`)
  }
  result = await executeIPTablesCommand(['-X', IPTABLES_FILTER_CHAIN])
  if (!result.success) {
    console.error(`Failed to delete filter chain ${IPTABLES_FILTER_CHAIN}. stderr: ${result.stderr}`)
  }
  console.warn('Custom iptables chains cleanup attempt complete.')
}

// --- NAT Rule Management ---

export async function addNATRule(): Promise<boolean> {
  console.warn(`Attempting to add NAT rule: redirect TCP traffic from port ${EXTERNAL_PORT} to ${INTERNAL_PORT}`)
  const args: string[] = ['-t', 'nat', '-A', IPTABLES_NAT_CHAIN, '-p', 'tcp', '--dport', String(EXTERNAL_PORT), '-j', 'REDIRECT', '--to-port', String(INTERNAL_PORT)]
  const checkArgs: string[] = args.map(arg => arg === '-A' ? '-C' : arg)
  const checkResult = await executeIPTablesCommand(checkArgs)
  if (checkResult.success) {
    console.warn(`NAT rule from ${EXTERNAL_PORT} to ${INTERNAL_PORT} already exists in ${IPTABLES_NAT_CHAIN}.`)
    return true
  }
  const result = await executeIPTablesCommand(args)
  if (!result.success) {
    console.error(`Failed to add NAT rule. stderr: ${result.stderr}`)
  }
  return result.success
}

export async function removeNATRule(): Promise<boolean> {
  console.warn(`Attempting to remove NAT rule: redirect TCP traffic from port ${EXTERNAL_PORT} to ${INTERNAL_PORT}`)
  const args: string[] = ['-t', 'nat', '-D', IPTABLES_NAT_CHAIN, '-p', 'tcp', '--dport', String(EXTERNAL_PORT), '-j', 'REDIRECT', '--to-port', String(INTERNAL_PORT)]
  const result = await executeIPTablesCommand(args)
  if (!result.success) {
    if (!(result.stderr?.includes('No chain/target/match by that name') || result.stderr?.includes('bad rule'))) {
      console.error(`Failed to remove NAT rule. stderr: ${result.stderr}`)
    }
  }
  return result.success
}

// --- Whitelist Rule Management ---

export async function addIPToWhitelist(ip: string): Promise<boolean> {
  const args: string[] = ['-A', IPTABLES_FILTER_CHAIN, '-s', ip, '-p', 'tcp', '--dport', String(EXTERNAL_PORT), '-j', 'ACCEPT']
  const result = await executeIPTablesCommand(args)
  return result.success
}

export async function listWhitelistedIPs(
  commandExecutor = executeIPTablesCommand,
): Promise<string[]> {
  const args: string[] = ['-S', IPTABLES_FILTER_CHAIN]
  const result = await commandExecutor(args)
  const ips: string[] = []
  if (result.success && result.stdout) {
    const rules = result.stdout.split('\n')
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?$/
    for (const rule of rules) {
      const trimmedRule = rule.trim()
      if (!trimmedRule.startsWith(`-A ${IPTABLES_FILTER_CHAIN}`)) {
        continue
      }
      const parts = trimmedRule.split(/\s+/)
      let sIndex = -1; let pIndex = -1; let dportIndex = -1; let jIndex = -1
      for (let i = 0; i < parts.length; i++) {
        if (parts[i] === '-s')
          sIndex = i
        else if (parts[i] === '-p')
          pIndex = i
        else if (parts[i] === '--dport')
          dportIndex = i
        else if (parts[i] === '-j')
          jIndex = i
      }
      if (sIndex !== -1 && (sIndex + 1) < parts.length
        && pIndex !== -1 && (pIndex + 1) < parts.length && parts[pIndex + 1] === 'tcp'
        && dportIndex !== -1 && (dportIndex + 1) < parts.length && parts[dportIndex + 1] === String(EXTERNAL_PORT)
        && jIndex !== -1 && (jIndex + 1) < parts.length && parts[jIndex + 1] === 'ACCEPT') {
        const potentialIp = parts[sIndex + 1]
        if (ipPattern.test(potentialIp)) {
          ips.push(potentialIp)
        }
      }
    }
  }
  else if (!result.success) {
    console.error(`Failed to list iptables rules in chain ${IPTABLES_FILTER_CHAIN}: ${result.stderr || 'Unknown error'}`)
  }
  return ips
}

export async function clearAllWhitelistRulesForPort(): Promise<{ success: boolean, removedCount: number }> {
  const listArgs: string[] = ['-S', IPTABLES_FILTER_CHAIN]
  const listResult = await executeIPTablesCommand(listArgs)
  let removedCount = 0
  let allDeletionsSuccessful = true
  if (listResult.success && listResult.stdout) {
    const rules = listResult.stdout.split('\n').filter(rule => rule.trim() !== '')
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?$/
    const rulesToDelete: string[] = []
    for (const rule of rules) {
      const trimmedRule = rule.trim()
      if (!trimmedRule.startsWith(`-A ${IPTABLES_FILTER_CHAIN}`)) {
        continue
      }
      const parts = trimmedRule.split(/\s+/)
      let sIndex = -1; let pIndex = -1; let dportIndex = -1; let jIndex = -1
      for (let i = 0; i < parts.length; i++) {
        if (parts[i] === '-s')
          sIndex = i
        else if (parts[i] === '-p')
          pIndex = i
        else if (parts[i] === '--dport')
          dportIndex = i
        else if (parts[i] === '-j')
          jIndex = i
      }
      if (sIndex !== -1 && (sIndex + 1) < parts.length
        && pIndex !== -1 && (pIndex + 1) < parts.length && parts[pIndex + 1] === 'tcp'
        && dportIndex !== -1 && (dportIndex + 1) < parts.length && parts[dportIndex + 1] === String(EXTERNAL_PORT)
        && jIndex !== -1 && (jIndex + 1) < parts.length && parts[jIndex + 1] === 'ACCEPT') {
        const potentialIp = parts[sIndex + 1]
        if (ipPattern.test(potentialIp)) {
          const ruleArgsPart = parts.slice(2).join(' ')
          rulesToDelete.push(ruleArgsPart)
        }
      }
    }
    if (rulesToDelete.length === 0) {
      console.warn(`No rules found for chain ${IPTABLES_FILTER_CHAIN} and port ${EXTERNAL_PORT} to delete.`)
      return { success: true, removedCount: 0 }
    }
    for (const rulePart of rulesToDelete) {
      const deleteArgs: string[] = ['-D', IPTABLES_FILTER_CHAIN, ...rulePart.split(' ')]
      const deleteResult = await executeIPTablesCommand(deleteArgs)
      if (deleteResult.success) {
        removedCount++
      }
      else {
        allDeletionsSuccessful = false
        console.error(`Failed to delete rule: iptables -D ${IPTABLES_FILTER_CHAIN} ${rulePart}`)
      }
    }
  }
  else if (!listResult.success) {
    console.error(`Failed to list iptables rules in chain ${IPTABLES_FILTER_CHAIN} before attempting cleanup. stderr: ${listResult.stderr}`)
    return { success: false, removedCount: 0 }
  }
  return { success: allDeletionsSuccessful, removedCount }
}
