import 'next-auth';
import 'next-auth/jwt';
import type { DefaultSession } from 'next-auth';

declare module 'next-auth' {
  interface Session {
    roles?: string[];
    tenantId?: string | null;
    experienceClass?: string;
    emailVerified: boolean;
    user: DefaultSession['user'] & {
      roles?: string[];
      tenantId?: string | null;
      experienceClass?: string;
    };
  }

  interface User {
    roles?: string[];
    tenantId?: string | null;
    experienceClass?: string;
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    roles?: string[];
    tenantId?: string | null;
    experienceClass?: string;
    emailVerified?: boolean;
    // AUTH-TENANT-CONTEXT-001: canonical principal UUID, projected from
    // https://frostgate.ai/principal_id by the Auth0 Post-Login Action.
    // Used by auth.ts to resolve tenant_id server-side at sign-in.
    principalId?: string | null;
  }
}
