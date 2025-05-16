import * as process from 'node:process'

// Original port for the application itself, distinct from EXTERNAL/INTERNAL ports for iptables
export const APP_PORT: number = Number(process.env.PORT) || 5000

// Load configuration from environment variables
export const SECRET_TOKEN: string | undefined = process.env.SECRET_TOKEN

// Ports for iptables forwarding rules
export const INTERNAL_PORT: number = Number(process.env.INTERNAL_PORT)
export const EXTERNAL_PORT: number = Number(process.env.EXTERNAL_PORT)

// Names for the custom iptables chains
export const IPTABLES_NAT_CHAIN: string = process.env.IPTABLES_NAT_CHAIN || 'VPN-NAT'
export const IPTABLES_FILTER_CHAIN: string = process.env.IPTABLES_FILTER_CHAIN || 'VPN-FILTER'

// Configuration for the iptables agent
export const IPTABLES_AGENT_HOST: string = process.env.IPTABLES_AGENT_HOST || 'host.docker.internal'
export const IPTABLES_AGENT_PORT: number = Number(process.env.IPTABLES_AGENT_PORT) || 12821

// --- Validations ---

if (!SECRET_TOKEN) {
  console.error('Error: SECRET_TOKEN environment variable not set.')
  process.exit(1)
}

if (Number.isNaN(EXTERNAL_PORT) || EXTERNAL_PORT <= 0) {
  console.error('Error: EXTERNAL_PORT environment variable must be a positive number.')
  process.exit(1)
}

if (Number.isNaN(INTERNAL_PORT) || INTERNAL_PORT <= 0) {
  console.error('Error: INTERNAL_PORT environment variable must be a positive number.')
  process.exit(1)
}

if (Number.isNaN(APP_PORT) || APP_PORT <= 0) {
  console.error('Error: PORT environment variable for the application must be a positive number.')
  process.exit(1)
}

if (Number.isNaN(IPTABLES_AGENT_PORT) || IPTABLES_AGENT_PORT <= 0) {
  console.error('Error: IPTABLES_AGENT_PORT environment variable must be a positive number.')
  process.exit(1)
}

console.warn('Configuration loaded successfully.')
