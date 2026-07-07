import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { canAccessConsoleRoute } from '@/lib/consoleAccess';

const { auth } = NextAuth(authConfig);

export default auth(function middleware(req: NextRequest & { auth: unknown }) {
  const isAuthenticated = !!(req as { auth?: unknown }).auth;
  const session = (req as { auth?: unknown }).auth;
  const { pathname } = req.nextUrl;

  // Public paths — never require auth
  const isPublic =
    pathname === '/' ||
    pathname === '/login' ||
    pathname === '/unauthorized' ||
    pathname.startsWith('/api/auth') ||
    pathname.startsWith('/onboarding') ||
    pathname.startsWith('/products');

  if (isPublic) return NextResponse.next();

  // redirect unauthenticated users to login, defaulting back to /dashboard
  if (!isAuthenticated) {
    const loginUrl = new URL('/login', req.url);
    // Only carry the callbackUrl forward for real app routes, not the landing page
    if (pathname !== '/') {
      loginUrl.searchParams.set('callbackUrl', pathname);
    }
    return NextResponse.redirect(loginUrl);
  }

  if (!pathname.startsWith('/api/') && !canAccessConsoleRoute(pathname, session)) {
    return NextResponse.redirect(new URL('/unauthorized', req.url));
  }

  return NextResponse.next();
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon\.ico).*)'],
};
