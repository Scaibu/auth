import dns from 'node:dns/promises';
import type { DnsResolverPort } from '../../../features/auth/ports/dns-resolver.port';

export class NodeDnsAdapter implements DnsResolverPort {
  private readonly resolver: dns.Resolver;

  constructor(servers?: string[]) {
    this.resolver = new dns.Resolver();
    if (servers && servers.length > 0) {
      this.resolver.setServers(servers);
    }
  }

  async resolveTxt(hostname: string): Promise<string[][]> {
    try {
      return await this.resolver.resolveTxt(hostname);
    } catch {
      return [];
    }
  }
}
