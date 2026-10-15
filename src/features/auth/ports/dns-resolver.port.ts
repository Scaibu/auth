export interface DnsResolverPort {
  resolveTxt(hostname: string): Promise<string[][]>;
}
