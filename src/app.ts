import type { Context, Next } from 'hono'
import * as process from 'node:process' // For process.on, process.exit
import { Hono } from 'hono'
import {
  EXTERNAL_PORT,
  IPTABLES_FILTER_CHAIN,
  SECRET_TOKEN,
} from './config'
import {
  addIPToWhitelist,
  addNATRule,
  cleanupChains,
  clearAllWhitelistRulesForPort,
  initializeChains,
  listWhitelistedIPs,
  removeNATRule,
} from './iptables'

const app = new Hono()

// --- Authentication Middleware ---
async function authMiddleware(c: Context, next: Next) {
  const token = c.req.query('token')
  if (token === SECRET_TOKEN) {
    await next()
  }
  else {
    console.warn(`Unauthorized attempt from ${c.req.header('x-forwarded-for') || c.req.header('remote-addr') || 'unknown IP'} to ${c.req.path}`)
    return c.json({ status: 'error', message: 'Invalid token' }, 401)
  }
}

// --- Route Handlers ---

// GET / - Health check
app.get('/', (c: Context) => {
  const clientIp = c.req.header('x-forwarded-for') || c.req.header('remote-addr')
  console.warn(`Health check request to / from ${clientIp || 'unknown IP'}`)
  return c.json({ status: 'healthy', message: 'Service is running.' })
})

// GET /list - View Whitelisted IPs (protected)
app.get('/list', authMiddleware, async (c: Context) => {
  const clientIp = c.req.header('x-forwarded-for') || c.req.header('remote-addr')
  try {
    console.warn(`Received valid GET /list request from ${clientIp || 'unknown IP'}. Listing IPs...`)
    const whitelistedIPs = await listWhitelistedIPs()
    return c.json({ status: 'success', count: whitelistedIPs.length, whitelisted_ips: whitelistedIPs })
  }
  catch (error: any) {
    console.error('Error listing whitelisted IPs for GET /list:', error)
    return c.json({ status: 'error', message: 'Failed to retrieve whitelisted IPs.' }, 500)
  }
})

// POST /whitelist - Add Client IP to Whitelist (protected)
app.post('/whitelist', authMiddleware, async (c: Context) => {
  let clientIp = c.req.header('x-forwarded-for') || c.req.header('remote-addr')
  if (clientIp && clientIp.includes(',')) {
    clientIp = clientIp.split(',')[0].trim()
  }

  if (!clientIp) {
    console.error('Could not determine client IP for /whitelist.')
    return c.json({ status: 'error', message: 'Could not determine client IP.' }, 400)
  }

  console.warn(`Received valid POST /whitelist request from ${clientIp}. Whitelisting...`)
  try {
    const addSuccess = await addIPToWhitelist(clientIp)
    if (addSuccess) {
      return c.json({
        status: 'success',
        message: `IP ${clientIp} whitelisted successfully for port ${EXTERNAL_PORT}.`,
        whitelisted_ip: clientIp,
        iptables_chain: IPTABLES_FILTER_CHAIN,
        vpn_port: EXTERNAL_PORT,
      })
    }
    else {
      return c.json({ status: 'error', message: `Failed to add iptables rule for ${clientIp}. Check container logs.` }, 500)
    }
  }
  catch (error: any) {
    console.error('An unhandled error occurred during /whitelist processing:', error)
    return c.json({ status: 'error', message: 'An internal server error occurred during whitelisting.' }, 500)
  }
})

// POST /cleanup - Remove All VPN Port Rules (protected)
app.post('/cleanup', authMiddleware, async (c: Context) => {
  const clientIp = c.req.header('x-forwarded-for') || c.req.header('remote-addr')
  try {
    console.warn(`Received valid POST /cleanup request from ${clientIp || 'unknown IP'}. Cleaning up rules...`)
    const cleanupResult = await clearAllWhitelistRulesForPort()
    if (cleanupResult.success) {
      return c.json({
        status: 'success',
        message: `Successfully processed cleanup for port ${EXTERNAL_PORT}. Removed ${cleanupResult.removedCount} rule(s).`,
        removed_count: cleanupResult.removedCount,
      })
    }
    else {
      return c.json({
        status: 'error',
        message: `Cleanup process for port ${EXTERNAL_PORT} encountered errors. Partially removed ${cleanupResult.removedCount} rule(s). Check logs.`,
        removed_count: cleanupResult.removedCount,
      }, 500)
    }
  }
  catch (error: any) {
    console.error('An unhandled error occurred during /cleanup processing:', error)
    return c.json({ status: 'error', message: 'An internal server error occurred during cleanup.' }, 500)
  }
})

// --- Startup and Shutdown Logic ---

// Function to initialize chains and add NAT rule on startup
async function startup() {
  try {
    await initializeChains()
    await addNATRule()
    console.warn('iptables chains initialized and NAT rule added successfully.')
  }
  catch (error) {
    console.error('Failed to initialize iptables chains or add NAT rule during startup:', error)
    process.exit(1) // Exit if critical startup tasks fail
  }
}

// Graceful shutdown handling
async function gracefulShutdown(signal: string) {
  console.warn(`Received ${signal}. Starting graceful shutdown...`)
  try {
    await removeNATRule()
    console.warn('NAT rule removed.')
    await cleanupChains()
    console.warn('iptables chains cleaned up.')
  }
  catch (error) {
    console.error('Error during NAT rule removal or chain cleanup on shutdown:', error)
  }
  process.exit(0)
}

// Attach shutdown listeners
process.on('SIGINT', () => gracefulShutdown('SIGINT'))
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))

// Perform startup tasks
startup()

export default app
