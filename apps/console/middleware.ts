import { auth } from '@/auth';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export default auth(function middleware(req: NextRequest & { auth: unknown }) {
  const isAuthenticated = !!(req as { auth?: unknown }).auth;
  const { pathname } = req.nextUrl;

  // always allow auth callbacks and static assets
  if (pathname.startsWith('/api/auth')) return NextResponse.next();

  // redirect unauthenticated users to login
  if (!isAuthenticated) {
    const loginUrl = new URL('/login', req.url);
    loginUrl.searchParams.set('callbackUrl', req.url);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon\\.ico).*)'],
};
