// Mock environment variables before importing modules
import { expect, mock, test } from 'bun:test'
import { IPTABLES_FILTER_CHAIN } from './config'
import { listWhitelistedIPs } from './iptables'

test('listWhitelistedIPs should correctly parse iptables output', async () => {
  // Create mock executor
  const mockExecutor = mock(async () => ({
    success: true,
    stdout: `-N ${IPTABLES_FILTER_CHAIN}\n-A ${IPTABLES_FILTER_CHAIN} -s 58.11.189.187/32 -p tcp -m tcp --dport 41872 -j ACCEPT`,
    stderr: '',
    exitCode: 0,
  }))

  const whitelistedIPs = await listWhitelistedIPs(mockExecutor)

  expect(whitelistedIPs).toEqual(['58.11.189.187/32'])
  expect(mockExecutor).toHaveBeenCalledWith(['-S', IPTABLES_FILTER_CHAIN])
})
