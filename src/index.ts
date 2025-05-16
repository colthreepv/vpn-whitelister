import app from './app'
import { APP_PORT } from './config'

console.warn(`Firewall Whitelist Service starting with Hono on port ${APP_PORT}`)

export default {
  port: APP_PORT,
  fetch: app.fetch,
}
