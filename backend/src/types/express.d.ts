import type { TokenPayload, Integration } from '@veltrix/shared';

declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
      tenantOrgId?: string;
      integration?: Integration;
    }
  }
}
