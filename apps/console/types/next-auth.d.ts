import 'next-auth';
import 'next-auth/jwt';
import type { DefaultSession } from 'next-auth';

declare module 'next-auth' {
  interface Session {
    roles?: string[];
    tenantId?: string | null;
    experienceClass?: string;
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
  }
}
