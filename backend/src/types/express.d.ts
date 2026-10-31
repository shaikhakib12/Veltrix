import type { TokenPayload } from '@veltrix/shared';

declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
      tenantOrgId?: string;
    }
  }
}
