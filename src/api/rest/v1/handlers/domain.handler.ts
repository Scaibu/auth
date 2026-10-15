import type { AuthService } from '../../../../features/auth/service';
import { UnauthorizedError } from '../../../../shared/errors/auth.errors';

export async function handleClaimDomain(
  service: AuthService,
  body: unknown,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to claim domain');
  }
  const input = (body && typeof body === 'object') ? body as any : {};
  return service.claimDomain(session.org.org_id, input);
}

export async function handleVerifyDomain(
  service: AuthService,
  domainId: string,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to verify domain');
  }
  return service.verifyDomain(domainId, session.org.org_id);
}

export async function handleListClaimedDomains(
  service: AuthService,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to list domains');
  }
  return service.listClaimedDomains(session.org.org_id);
}

export async function handleUpdateDomainSettings(
  service: AuthService,
  domainId: string,
  body: unknown,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to update domain settings');
  }
  const patch = (body && typeof body === 'object') ? body as any : {};
  return service.updateDomainSettings(domainId, session.org.org_id, patch);
}

export async function handleDeleteClaimedDomain(
  service: AuthService,
  domainId: string,
  session?: { sub: string; org?: { org_id: string } },
) {
  if (!session?.org?.org_id) {
    throw new UnauthorizedError('Organization context required to delete claimed domain');
  }
  return service.deleteClaimedDomain(domainId, session.org.org_id);
}

export async function handleListBlockedDomains(
  service: AuthService,
  session?: { sub: string; role?: string; org?: { role?: string } },
) {
  const userRole = session?.role ?? session?.org?.role;
  if (userRole !== 'admin' && userRole !== 'SUPER_ADMIN') {
    throw new UnauthorizedError('Administrator privileges required to view blocked domains');
  }
  return service.listBlockedDomains();
}

export async function handleAddBlockedDomain(
  service: AuthService,
  body: unknown,
  session?: { sub: string; role?: string; org?: { role?: string } },
) {
  const userRole = session?.role ?? session?.org?.role;
  if (userRole !== 'admin' && userRole !== 'SUPER_ADMIN') {
    throw new UnauthorizedError('Administrator privileges required to add blocked domains');
  }
  const input = (body && typeof body === 'object') ? body as any : {};
  return service.addBlockedDomain(input);
}

export async function handleRemoveBlockedDomain(
  service: AuthService,
  domain: string,
  session?: { sub: string; role?: string; org?: { role?: string } },
) {
  const userRole = session?.role ?? session?.org?.role;
  if (userRole !== 'admin' && userRole !== 'SUPER_ADMIN') {
    throw new UnauthorizedError('Administrator privileges required to remove blocked domains');
  }
  return service.removeBlockedDomain(domain);
}


