import type { Server } from 'bun' // Added for Server type hint
import * as process from 'node:process'

const port: number = Number(process.env.PORT) || 5000 // Internal port for the app

// Load configuration from environment variables
const SECRET_TOKEN: string | undefined = process.env.SECRET_TOKEN

// New environment variables from plan.md
const INTERNAL_PORT: number = Number(process.env.INTERNAL_PORT)
const EXTERNAL_PORT: number = Number(process.env.EXTERNAL_PORT)
const IPTABLES_NAT_CHAIN: string = process.env.IPTABLES_NAT_CHAIN || 'VPN-NAT'
const IPTABLES_FILTER_CHAIN: string = process.env.IPTABLES_FILTER_CHAIN || 'VPN-FILTER'

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

// New helper function for iptables commands using Bun.spawn (Section III.1, IV.2)
async function executeIPTablesCommand(args: string[]): Promise<{ success: boolean, stdout?: string, stderr?: string }> {
  const command = ['sudo', 'iptables', ...args]
  console.warn(`Executing Bun.spawn: ${command.join(' ')}`)
  try {
    const proc = Bun.spawn(command, {
      stdout: 'pipe',
      stderr: 'pipe',
    })
    const stdout = await new Response(proc.stdout).text()
    const stderr = await new Response(proc.stderr).text()
    const exitCode = await proc.exited

    if (stdout.trim()) {
      console.warn(`iptables stdout: ${stdout.trim()}`)
    }
    if (stderr.trim()) {
      // Don't log stderr as warning if it's a "no rule found for -D" type of message, as it's expected.
      const isExpectedStderrForDelete = args[0] === '-D'
        && (stderr.includes('No chain/target/match by that name')
          || stderr.includes('bad rule') // e.g. "iptables: Bad rule (does a matching rule exist in that chain?)."
          || stderr.includes('rule is not in chain')) // Another variant
      if (!isExpectedStderrForDelete) {
        console.warn(`iptables stderr: ${stderr.trim()}`)
      }
    }

    if (exitCode === 0) {
      return { success: true, stdout: stdout.trim(), stderr: stderr.trim() }
    }
    else {
      // Specific handling for -D if rule doesn't exist (Section II.3, Plan V.Error Handling)
      if (args[0] === '-D'
        && (stderr.includes('No chain/target/match by that name')
          || stderr.includes('bad rule') // e.g. "iptables: Bad rule (does a matching rule exist in that chain?)."
          || stderr.includes('rule is not in chain'))) { // Another variant
        console.warn(`Attempted to remove non-existent or already removed rule (expected for -D sometimes): ${command.join(' ')}`)
        return { success: true, stdout: stdout.trim(), stderr: stderr.trim() } // Still consider it a "success" for cleanup logic
      }
      console.error(`iptables command failed with exit code ${exitCode}: ${command.join(' ')} Stderr: ${stderr.trim()}`)
      return { success: false, stdout: stdout.trim(), stderr: stderr.trim() }
    }
  }
  catch (error: any) {
    console.error(`Bun.spawn for iptables command failed: ${error.message}`)
    return { success: false, stderr: error.message }
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
    const clientIp = server.requestIP(request)?.address

    // GET / - View Whitelisted IPs (Section II.1)
    if (url.pathname === '/' && request.method === 'GET') {
      if (!isAuthenticated(request)) {
        console.warn(`Unauthorized GET / attempt from ${clientIp || 'unknown IP'}`)
        return new Response(JSON.stringify({ status: 'error', message: 'Invalid token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      try {
        console.warn(`Received valid GET / request from ${clientIp || 'unknown IP'}. Listing IPs...`)
        const whitelistedIPs = await listWhitelistedIPs()
        return new Response(JSON.stringify({ status: 'success', count: whitelistedIPs.length, whitelisted_ips: whitelistedIPs }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      catch (error: any) {
        console.error('Error listing whitelisted IPs for GET /:', error)
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
