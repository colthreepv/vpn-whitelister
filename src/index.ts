import type { Server } from 'bun' // Added for Server type hint
import { Buffer } from 'node:buffer' // Added for Buffer
import * as process from 'node:process'

const port: number = Number(process.env.PORT) || 5000 // Internal port for the app

// Load configuration from environment variables
const SECRET_TOKEN: string | undefined = process.env.SECRET_TOKEN

// New environment variables from plan.md
const INTERNAL_PORT: number = Number(process.env.INTERNAL_PORT)
const EXTERNAL_PORT: number = Number(process.env.EXTERNAL_PORT)
const IPTABLES_NAT_CHAIN: string = process.env.IPTABLES_NAT_CHAIN || 'VPN-NAT'
const IPTABLES_FILTER_CHAIN: string = process.env.IPTABLES_FILTER_CHAIN || 'VPN-FILTER'

// Environment variables for the iptables agent
const IPTABLES_AGENT_HOST: string = process.env.IPTABLES_AGENT_HOST || 'host.docker.internal'
const IPTABLES_AGENT_PORT: number = Number(process.env.IPTABLES_AGENT_PORT) || 12821

if (!SECRET_TOKEN) {
  console.error('Error: SECRET_TOKEN environment variable not set.')
  process.exit(1)
}

// It's good practice to ensure EXTERNAL_PORT and INTERNAL_PORT are set if they are critical
if (Number.isNaN(EXTERNAL_PORT) || EXTERNAL_PORT <= 0) {
  console.error('Error: EXTERNAL_PORT environment variable must be a positive number.')
  process.exit(1)
}

if (Number.isNaN(INTERNAL_PORT) || INTERNAL_PORT <= 0) {
  console.error('Error: INTERNAL_PORT environment variable must be a positive number.')
  process.exit(1)
}

// Helper function to authenticate requests (Section III.1)
function isAuthenticated(request: Request): boolean {
  const url = new URL(request.url)
  const token = url.searchParams.get('token')
  // TODO: Consider supporting Authorization: Bearer token
  return token === SECRET_TOKEN
}

// New helper function for iptables commands using the agent (replaces old Bun.spawn version)
async function executeIPTablesCommand(args: string[]): Promise<{ success: boolean, stdout?: string, stderr?: string, exitCode?: number }> {
  const commandString = args.join(' ')
  console.warn(`Agent CMD: iptables ${commandString}`)

  return new Promise((resolve, reject) => {
    let socket: any // Bun.TCPSocket - type hint if available, else any
    let rawOutput = ''
    let connectionOpened = false

    const timeout = setTimeout(() => {
      if (socket) {
        socket.end() // Attempt to close the socket on timeout
      }
      // Reject the main promise
      reject(new Error(`Agent response timeout for: iptables ${commandString}`))
    }, 10000) // 10s timeout

    try {
      socket = Bun.connect({
        hostname: IPTABLES_AGENT_HOST,
        port: IPTABLES_AGENT_PORT,
        socket: {
          data(_socket, data) {
            rawOutput += Buffer.from(data).toString()
            // Potentially check here if rawOutput contains "---END---" to resolve early
            // However, relying on 'close' event is often more robust for TCP streams
          },
          open(sock) {
            connectionOpened = true
            // console.log('Socket opened to agent')
            sock.write(`${commandString}\n`)
            sock.flush()
          },
          close(_socket) {
            // console.log('Socket to agent closed')
            clearTimeout(timeout)
            if (!connectionOpened) {
              // If connection never opened, it might be an immediate connection refusal
              // The error event or main try/catch should ideally handle this.
              // However, if close is called before open and without an error, reject.
              return reject(new Error(`Agent connection closed before opening for: iptables ${commandString}`))
            }
            if (rawOutput.includes('---END---')) {
              // --- Parsing agent's response (moved inside close) ---
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
                  break // Stop parsing after ---END---
                }
                else if (currentSection === 'stdout') {
                  stdout += (stdout ? '\n' : '') + line
                }
                else if (currentSection === 'stderr') {
                  stderr += (stderr ? '\n' : '') + line
                }
              }
              // Resolve with parsed data
              resolve(processAgentResponse(args, commandString, exitCode, stdout, stderr))
            }
            else {
              // If stream closed without ---END---, it's an incomplete or errored response
              reject(new Error(`Agent response incomplete for: iptables ${commandString}. Received: ${rawOutput.substring(0, 200)}...`))
            }
          },
          error(sock, error) {
            // console.error(`Agent socket error: ${error.message}`)
            clearTimeout(timeout)
            if (socket)
              socket.end() // Ensure socket is closed on error
            reject(new Error(`Agent socket error for 'iptables ${commandString}': ${error.message}`))
          },
        },
      })
    }
    catch (error: any) {
      clearTimeout(timeout)
      // This catch is for synchronous errors during Bun.connect() call itself
      console.error(`Synchronous Bun.connect error for 'iptables ${commandString}': ${error.message}`)
      reject(new Error(`Agent connection setup error for 'iptables ${commandString}': ${error.message}`))
    }
  })
}

// Helper function to process the agent's response and determine success/failure
// This encapsulates the logic previously at the end of executeIPTablesCommand
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
    'is not a chain', // for -X on a rule not a chain
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

// Function to initialize custom iptables chains
async function initializeChains(): Promise<void> {
  console.warn('Initializing custom iptables chains...')

  // NAT Chain Setup
  let result = await executeIPTablesCommand(['-t', 'nat', '-N', IPTABLES_NAT_CHAIN])
  if (!result.success) {
    console.error(`Failed to create NAT chain ${IPTABLES_NAT_CHAIN}. stderr: ${result.stderr}`)
    // Potentially exit or handle error more gracefully depending on requirements
  }

  // Check if the PREROUTING jump rule already exists
  result = await executeIPTablesCommand(['-t', 'nat', '-C', 'PREROUTING', '-j', IPTABLES_NAT_CHAIN])
  if (!result.success) { // If check fails, rule doesn't exist, so add it
    result = await executeIPTablesCommand(['-t', 'nat', '-A', 'PREROUTING', '-j', IPTABLES_NAT_CHAIN])
    if (!result.success) {
      console.error(`Failed to link NAT chain ${IPTABLES_NAT_CHAIN} to PREROUTING. stderr: ${result.stderr}`)
    }
  }
  else {
    console.warn(`Rule to jump from PREROUTING to ${IPTABLES_NAT_CHAIN} already exists.`)
  }

  // Filter Chain Setup
  result = await executeIPTablesCommand(['-N', IPTABLES_FILTER_CHAIN])
  if (!result.success) {
    console.error(`Failed to create filter chain ${IPTABLES_FILTER_CHAIN}. stderr: ${result.stderr}`)
  }

  // Check if the INPUT jump rule already exists
  result = await executeIPTablesCommand(['-C', 'INPUT', '-j', IPTABLES_FILTER_CHAIN])
  if (!result.success) { // If check fails, rule doesn't exist, so add it
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

// Function to clean up custom iptables chains
async function cleanupChains(): Promise<void> {
  console.warn('Cleaning up custom iptables chains...')
  let result

  // Unlink from PREROUTING (NAT)
  // Check if the rule exists before trying to delete
  result = await executeIPTablesCommand(['-t', 'nat', '-C', 'PREROUTING', '-j', IPTABLES_NAT_CHAIN])
  if (result.success) { // Rule exists, so delete it
    result = await executeIPTablesCommand(['-t', 'nat', '-D', 'PREROUTING', '-j', IPTABLES_NAT_CHAIN])
    if (!result.success) {
      console.error(`Failed to unlink NAT chain ${IPTABLES_NAT_CHAIN} from PREROUTING. stderr: ${result.stderr}`)
    }
  }
  else {
    console.warn(`Jump rule from PREROUTING to ${IPTABLES_NAT_CHAIN} does not exist or already removed.`)
  }

  // Flush NAT chain
  result = await executeIPTablesCommand(['-t', 'nat', '-F', IPTABLES_NAT_CHAIN])
  if (!result.success) {
    console.error(`Failed to flush NAT chain ${IPTABLES_NAT_CHAIN}. stderr: ${result.stderr}`)
  }

  // Delete NAT chain
  result = await executeIPTablesCommand(['-t', 'nat', '-X', IPTABLES_NAT_CHAIN])
  if (!result.success) {
    console.error(`Failed to delete NAT chain ${IPTABLES_NAT_CHAIN}. stderr: ${result.stderr}`)
    // This can fail if there are still rules referencing it (e.g. from PREROUTING if unlink failed)
  }

  // Unlink from INPUT (Filter)
  // Check if the rule exists before trying to delete
  result = await executeIPTablesCommand(['-C', 'INPUT', '-j', IPTABLES_FILTER_CHAIN])
  if (result.success) { // Rule exists, so delete it
    result = await executeIPTablesCommand(['-D', 'INPUT', '-j', IPTABLES_FILTER_CHAIN])
    if (!result.success) {
      console.error(`Failed to unlink filter chain ${IPTABLES_FILTER_CHAIN} from INPUT. stderr: ${result.stderr}`)
    }
  }
  else {
    console.warn(`Jump rule from INPUT to ${IPTABLES_FILTER_CHAIN} does not exist or already removed.`)
  }

  // Flush Filter chain
  result = await executeIPTablesCommand(['-F', IPTABLES_FILTER_CHAIN])
  if (!result.success) {
    console.error(`Failed to flush filter chain ${IPTABLES_FILTER_CHAIN}. stderr: ${result.stderr}`)
  }

  // Delete Filter chain
  result = await executeIPTablesCommand(['-X', IPTABLES_FILTER_CHAIN])
  if (!result.success) {
    console.error(`Failed to delete filter chain ${IPTABLES_FILTER_CHAIN}. stderr: ${result.stderr}`)
    // This can fail if there are still rules referencing it (e.g. from INPUT if unlink failed)
  }

  console.warn('Custom iptables chains cleanup attempt complete.')
}

// Function to add NAT rule for port forwarding
async function addNATRule(): Promise<boolean> {
  console.warn(`Attempting to add NAT rule: redirect TCP traffic from port ${EXTERNAL_PORT} to ${INTERNAL_PORT}`)
  const args: string[] = [
    '-t',
    'nat',
    '-A',
    IPTABLES_NAT_CHAIN,
    '-p',
    'tcp',
    '--dport',
    String(EXTERNAL_PORT),
    '-j',
    'REDIRECT',
    '--to-port',
    String(INTERNAL_PORT),
  ]
  // Check if the rule already exists to prevent duplicates and avoid command failure indication
  const checkArgs: string[] = args.map(arg => arg === '-A' ? '-C' : arg) // Replace -A with -C for check
  const checkResult = await executeIPTablesCommand(checkArgs)
  if (checkResult.success) {
    console.warn(`NAT rule from ${EXTERNAL_PORT} to ${INTERNAL_PORT} already exists in ${IPTABLES_NAT_CHAIN}.`)
    return true // Rule already exists, consider it a success
  }

  const result = await executeIPTablesCommand(args)
  if (!result.success) {
    console.error(`Failed to add NAT rule. stderr: ${result.stderr}`)
  }
  return result.success
}

// Function to remove NAT rule for port forwarding
async function removeNATRule(): Promise<boolean> {
  console.warn(`Attempting to remove NAT rule: redirect TCP traffic from port ${EXTERNAL_PORT} to ${INTERNAL_PORT}`)
  const args: string[] = [
    '-t',
    'nat',
    '-D',
    IPTABLES_NAT_CHAIN,
    '-p',
    'tcp',
    '--dport',
    String(EXTERNAL_PORT),
    '-j',
    'REDIRECT',
    '--to-port',
    String(INTERNAL_PORT),
  ]
  const result = await executeIPTablesCommand(args)
  if (!result.success) {
    // Do not log error if it's because the rule didn't exist (common for -D)
    if (!(result.stderr?.includes('No chain/target/match by that name') || result.stderr?.includes('bad rule'))) {
      console.error(`Failed to remove NAT rule. stderr: ${result.stderr}`)
    }
  }
  return result.success
}

// Re-implement addIpRule using the new executeIPTablesCommand (Section III.1)
async function addIPToWhitelist(ip: string): Promise<boolean> {
  const args: string[] = ['-A', IPTABLES_FILTER_CHAIN, '-s', ip, '-p', 'tcp', '--dport', String(EXTERNAL_PORT), '-j', 'ACCEPT']
  const result = await executeIPTablesCommand(args)
  return result.success
}

// Helper to list whitelisted IPs (Section III.1)
async function listWhitelistedIPs(): Promise<string[]> {
  const args: string[] = ['-S', IPTABLES_FILTER_CHAIN]
  const result = await executeIPTablesCommand(args)
  const ips: string[] = []

  if (result.success && result.stdout) {
    const rules = result.stdout.split('\n')
    const ipRegex = new RegExp(`^-A ${IPTABLES_FILTER_CHAIN} -s (\\d{1,3}\\.?\\d{1,3}\\.?\\d{1,3}\\.?\\d{1,3}(?:/\\d{1,2})?) .* -p tcp .* --dport ${EXTERNAL_PORT} -j ACCEPT$`)
    for (const rule of rules) {
      const match = rule.match(ipRegex)
      if (match && match[1]) {
        ips.push(match[1])
      }
    }
  }
  return ips
}

// Helper to clear all whitelist rules for the specific port (Section III.1)
async function clearAllWhitelistRulesForPort(): Promise<{ success: boolean, removedCount: number }> {
  const listArgs: string[] = ['-S', IPTABLES_FILTER_CHAIN]
  const listResult = await executeIPTablesCommand(listArgs)
  let removedCount = 0
  let allDeletionsSuccessful = true

  if (listResult.success && listResult.stdout) {
    const rules = listResult.stdout.split('\n').filter(rule => rule.trim() !== '')
    // Filter rules that are for our specific port and ACCEPT
    const relevantRuleRegex = new RegExp(`^-A ${IPTABLES_FILTER_CHAIN} -s (\\d{1,3}\\.?\\d{1,3}\\.?\\d{1,3}\\.?\\d{1,3}(?:/\\d{1,2})?) .* -p tcp .* --dport ${EXTERNAL_PORT} -j ACCEPT$`)

    const rulesToDelete: string[] = []
    for (const rule of rules) {
      if (relevantRuleRegex.test(rule)) {
        // Construct the delete command arguments from the rule string
        // Example rule string: "-A VPN-FILTER -s 1.2.3.4/32 -p tcp -m tcp --dport 41872 -j ACCEPT"
        // We need to pass everything after "-A CHAIN_NAME " to "-D CHAIN_NAME"
        const ruleArgsPart = rule.substring(`-A ${IPTABLES_FILTER_CHAIN} `.length)
        rulesToDelete.push(ruleArgsPart)
      }
    }

    if (rulesToDelete.length === 0) {
      console.warn(`No rules found for chain ${IPTABLES_FILTER_CHAIN} and port ${EXTERNAL_PORT} to delete.`)
      return { success: true, removedCount: 0 }
    }

    // Delete rules one by one.
    // It's generally safer to delete by exact rule specification.
    for (const rulePart of rulesToDelete) {
      // Split rulePart into arguments for executeIPTablesCommand
      // This needs careful handling if there are quoted arguments in the future, but for typical iptables rules this should be okay.
      const deleteArgs: string[] = ['-D', IPTABLES_FILTER_CHAIN, ...rulePart.split(' ')]
      const deleteResult = await executeIPTablesCommand(deleteArgs)
      if (deleteResult.success) {
        removedCount++
      }
      else {
        allDeletionsSuccessful = false
        // Error already logged by executeIPTablesCommand
        console.error(`Failed to delete rule: iptables -D ${IPTABLES_FILTER_CHAIN} ${rulePart}`)
      }
    }
  }
  else if (!listResult.success) {
    console.error(`Failed to list iptables rules in chain ${IPTABLES_FILTER_CHAIN} before attempting cleanup.`)
    return { success: false, removedCount: 0 }
  }

  return { success: allDeletionsSuccessful, removedCount }
}

// Initialize chains on startup
initializeChains().then(() => {
  // After chains are initialized, add the NAT rule
  return addNATRule()
}).catch((error) => {
  console.error('Failed to initialize iptables chains or add NAT rule during startup:', error)
  // Depending on policy, might want to process.exit(1) here if critical
})

console.warn(`Firewall Whitelist Service will listen internally on port ${port}`)

Bun.serve({
  port,
  async fetch(request: Request, server: Server) {
    const url = new URL(request.url)

    // Determine client IP, prioritizing X-Forwarded-For header
    const forwardedFor = request.headers.get('x-forwarded-for')
    let clientIp = server.requestIP(request)?.address // Fallback
    if (forwardedFor) {
      // X-Forwarded-For can be a comma-separated list (client, proxy1, proxy2)
      // The first IP is the original client IP.
      clientIp = forwardedFor.split(',')[0].trim()
    }

    // GET / - Simple health check endpoint (moved from /health)
    if (url.pathname === '/' && request.method === 'GET') {
      console.warn(`Health check request to / from ${clientIp || 'unknown IP'}`)
      return new Response(JSON.stringify({ status: 'healthy', message: 'Service is running.' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    // GET /list - View Whitelisted IPs (moved from /)
    else if (url.pathname === '/list' && request.method === 'GET') {
      if (!isAuthenticated(request)) {
        console.warn(`Unauthorized GET /list attempt from ${clientIp || 'unknown IP'}`)
        return new Response(JSON.stringify({ status: 'error', message: 'Invalid token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      try {
        console.warn(`Received valid GET /list request from ${clientIp || 'unknown IP'}. Listing IPs...`)
        const whitelistedIPs = await listWhitelistedIPs()
        return new Response(JSON.stringify({ status: 'success', count: whitelistedIPs.length, whitelisted_ips: whitelistedIPs }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      catch (error: any) {
        console.error('Error listing whitelisted IPs for GET /list:', error)
        return new Response(JSON.stringify({ status: 'error', message: 'Failed to retrieve whitelisted IPs.' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        })
      }
    }

    // POST /whitelist - Add Client IP to Whitelist (Section II.2)
    else if (url.pathname === '/whitelist' && request.method === 'POST') {
      if (!isAuthenticated(request)) {
        console.warn(`Unauthorized POST /whitelist attempt from ${clientIp || 'unknown IP'}`)
        return new Response(JSON.stringify({ status: 'error', message: 'Invalid token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        })
      }

      if (!clientIp) {
        console.error('Could not determine client IP for /whitelist.')
        return new Response(JSON.stringify({ status: 'error', message: 'Could not determine client IP.' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        })
      }

      console.warn(`Received valid POST /whitelist request from ${clientIp}. Whitelisting...`)

      try {
        const addSuccess: boolean = await addIPToWhitelist(clientIp)

        if (addSuccess) {
          return new Response(
            JSON.stringify({
              status: 'success',
              message: `IP ${clientIp} whitelisted successfully for port ${EXTERNAL_PORT}.`,
              whitelisted_ip: clientIp,
              iptables_chain: IPTABLES_FILTER_CHAIN,
              vpn_port: EXTERNAL_PORT,
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            },
          )
        }
        else {
          return new Response(JSON.stringify({ status: 'error', message: `Failed to add iptables rule for ${clientIp}. Check container logs.` }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
          })
        }
      }
      catch (error: any) {
        console.error('An unhandled error occurred during /whitelist processing:', error)
        return new Response(JSON.stringify({ status: 'error', message: 'An internal server error occurred during whitelisting.' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        })
      }
    }

    // POST /cleanup - Remove All VPN Port Rules (Section II.3)
    else if (url.pathname === '/cleanup' && request.method === 'POST') {
      if (!isAuthenticated(request)) {
        console.warn(`Unauthorized POST /cleanup attempt from ${clientIp || 'unknown IP'}`)
        return new Response(JSON.stringify({ status: 'error', message: 'Invalid token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      try {
        console.warn(`Received valid POST /cleanup request from ${clientIp || 'unknown IP'}. Cleaning up rules...`)
        const cleanupResult = await clearAllWhitelistRulesForPort()
        if (cleanupResult.success) {
          return new Response(
            JSON.stringify({
              status: 'success',
              message: `Successfully processed cleanup for port ${EXTERNAL_PORT}. Removed ${cleanupResult.removedCount} rule(s).`,
              removed_count: cleanupResult.removedCount,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          )
        }
        else {
          return new Response(
            JSON.stringify({
              status: 'error',
              message: `Cleanup process for port ${EXTERNAL_PORT} encountered errors. Partially removed ${cleanupResult.removedCount} rule(s). Check logs.`,
              removed_count: cleanupResult.removedCount,
            }),
            { status: 500, headers: { 'Content-Type': 'application/json' } },
          )
        }
      }
      catch (error: any) {
        console.error('An unhandled error occurred during /cleanup processing:', error)
        return new Response(JSON.stringify({ status: 'error', message: 'An internal server error occurred during cleanup.' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        })
      }
    }

    // Fallback for other paths/methods
    else {
      return new Response(JSON.stringify({ status: 'error', message: `Endpoint not found or method not allowed for ${request.method} ${url.pathname}.` }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      })
    }
  },
  error(error: Error) {
    console.error('Unhandled error in Bun.serve:', error)
    return new Response(JSON.stringify({ status: 'error', message: 'An internal server error occurred in Bun.serve.' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    })
  },
})

// Graceful shutdown handling
async function gracefulShutdown(signal: string) {
  console.warn(`Received ${signal}. Starting graceful shutdown...`)
  try {
    await removeNATRule() // Remove NAT rule first
    console.warn('NAT rule removed.')
    await cleanupChains()
    console.warn('iptables chains cleaned up.')
  }
  catch (error) {
    console.error('Error during NAT rule removal or chain cleanup on shutdown:', error)
  }
  process.exit(0)
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'))
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
