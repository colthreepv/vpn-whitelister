import { Buffer } from 'node:buffer'
import { exec } from 'node:child_process'
import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { promisify } from 'node:util'

const execAsync = promisify(exec)

const port: number = Number(process.env.PORT) || 5000 // Internal port for the app

// Load configuration from environment variables
const SECRET_TOKEN: string | undefined = process.env.SECRET_TOKEN
const IPTABLES_CHAIN: string = process.env.IPTABLES_CHAIN || 'INPUT' // Default iptables chain
const VPN_PORT: string = process.env.VPN_PORT || '41872' // Default VPN port
const STATE_FILE: string = process.env.STATE_FILE || '/app/state/last_whitelisted_ip.txt' // File to store the last IP

if (!SECRET_TOKEN) {
  console.error('Error: SECRET_TOKEN environment variable not set.')
  process.exit(1)
}

const stateFilePath: string = path.resolve(STATE_FILE)

async function readLastIP(): Promise<string | null> {
  try {
    const data: string = await fs.readFile(stateFilePath, 'utf8')
    return data.trim()
  }
  catch (error: any) {
    if (error.code === 'ENOENT') {
      // File doesn't exist, first run
      return null
    }
    console.error(`Error reading state file ${stateFilePath}:`, error)
    return null // Return null on other errors too
  }
}

async function writeLastIP(ip: string): Promise<void> {
  try {
    // Ensure directory exists
    await fs.mkdir(path.dirname(stateFilePath), { recursive: true })
    await fs.writeFile(stateFilePath, ip, 'utf8')
    console.warn(`Wrote last whitelisted IP (${ip}) to state file.`)
  }
  catch (error: any) {
    console.error(`Error writing state file ${stateFilePath}:`, error)
  }
}

async function runIptablesCommand(args: string[]): Promise<boolean> {
  const command = `iptables ${args.join(' ')}`
  console.warn(`Running iptables command: ${command}`)
  try {
    const { stdout, stderr } = await execAsync(command) as { stdout: string | Buffer, stderr: string | Buffer }
    if (stdout) {
      const stdoutString = Buffer.isBuffer(stdout) ? stdout.toString().trim() : stdout.trim()
      console.warn(`iptables stdout: ${stdoutString}`)
    }
    if (stderr) {
      const stderrString = Buffer.isBuffer(stderr) ? stderr.toString().trim() : stderr.trim()
      console.warn(`iptables stderr: ${stderrString}`)
    }
    return true // Command succeeded
  }
  catch (error: any) {
    console.error(`iptables command failed: ${error.message}`)
    // iptables -D for a non-existent rule returns an error, which is expected sometimes.
    // We'll check if the error indicates "no matching rule" to suppress noisy logs for removal attempts.
    if (args[0] === '-D' && (error.message.includes('No chain/target/match by that name') || error.message.includes('bad rule'))) {
      console.warn(`Attempted to remove non-existent rule (expected for -D sometimes): ${command}`)
      return true // Consider removal attempts 'successful' if the rule wasn't there
    }
    return false // Command failed unexpectedly
  }
}

async function removeIpRule(ip: string): Promise<void> {
  const args: string[] = ['-D', IPTABLES_CHAIN, '-s', ip, '-p', 'tcp', '--dport', VPN_PORT, '-j', 'ACCEPT']
  // We don't strictly need to check the return for -D as it fails if the rule doesn't exist.
  // The runIptablesCommand helper handles the expected error message.
  await runIptablesCommand(args)
}

async function addIpRule(ip: string): Promise<boolean> {
  const args: string[] = ['-A', IPTABLES_CHAIN, '-s', ip, '-p', 'tcp', '--dport', VPN_PORT, '-j', 'ACCEPT']
  return runIptablesCommand(args) // Return true/false based on execution success
}

console.warn(`Firewall Whitelist Service will listen internally on port ${port}`)

Bun.serve({
  port,
  fetch(request, server) {
    const url = new URL(request.url)
    const clientIp = server.requestIP(request)?.address

    if (url.pathname === '/') {
      return new Response('Firewall Whitelist Service is running.', { status: 200 })
    }

    if (url.pathname === '/whitelist') {
      const token = url.searchParams.get('token')

      if (token !== SECRET_TOKEN) {
        console.warn(`Unauthorized attempt from ${clientIp || 'unknown IP'} with invalid token.`)
        return new Response(JSON.stringify({ status: 'error', message: 'Invalid token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        })
      }

      if (!clientIp) {
        console.error('Could not determine client IP.')
        return new Response(JSON.stringify({ status: 'error', message: 'Could not determine client IP.' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        })
      }

      console.warn(`Received valid request from ${clientIp}. Whitelisting...`)

      return (async () => {
        try {
          const lastWhitelistedIp: string | null = await readLastIP()

          if (lastWhitelistedIp && lastWhitelistedIp !== clientIp) {
            console.warn(`Last whitelisted IP was ${lastWhitelistedIp}. Removing rule for it.`)
            await removeIpRule(lastWhitelistedIp)
          }
          else if (lastWhitelistedIp === clientIp) {
            console.warn(`IP ${clientIp} is already the last whitelisted IP. Attempting to ensure rule exists.`)
          }
          else {
            console.warn('No previous IP found in state file.')
          }

          const addSuccess: boolean = await addIpRule(clientIp)

          if (addSuccess) {
            await writeLastIP(clientIp)
            return new Response(
              JSON.stringify({
                status: 'success',
                message: `IP ${clientIp} whitelisted successfully for port ${VPN_PORT}.`,
                whitelisted_ip: clientIp,
                iptables_chain: IPTABLES_CHAIN,
                vpn_port: VPN_PORT,
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
          console.error('An unhandled error occurred during whitelisting:', error)
          return new Response(JSON.stringify({ status: 'error', message: 'An internal server error occurred.' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
          })
        }
      })()
    }

    return new Response('Not found', { status: 404 })
  },
  error(error) {
    console.error('Unhandled error in Bun.serve:', error)
    return new Response('Internal Server Error', { status: 500 })
  },
})
