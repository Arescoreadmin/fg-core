import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { sendMail } from '@/lib/mailer';

const PORTAL_ORIGIN =
  process.env.PORTAL_URL ||
  process.env.NEXT_PUBLIC_PORTAL_URL ||
  'https://app.frostgate.ai';

const CONSOLE_ORIGIN =
  process.env.NEXTAUTH_URL ||
  process.env.NEXT_PUBLIC_APP_URL ||
  'https://console.frostgate.ai';

// ─── Invite email ─────────────────────────────────────────────────────────────

function consoleInviteHtml(name: string, inviteUrl: string, tenantLabel: string) {
  return `<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;border:1px solid #e2e8f0;padding:40px;">
<tr><td>
  <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#0f172a;">You're invited to FrostGate</p>
  <p style="margin:0 0 24px;font-size:14px;color:#64748b;">${tenantLabel} workspace</p>
  <p style="margin:0 0 20px;font-size:15px;color:#334155;">Hi ${name},</p>
  <p style="margin:0 0 28px;font-size:15px;color:#334155;line-height:1.6;">
    You've been invited to access the <strong>FrostGate AI Governance Console</strong> for <strong>${tenantLabel}</strong>.
    Click the button below to set up your account. This link expires in <strong>72 hours</strong>.
  </p>
  <p style="margin:0 0 32px;">
    <a href="${inviteUrl}" style="display:inline-block;padding:12px 28px;background:#2563eb;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;font-size:15px;">Accept invitation</a>
  </p>
  <p style="margin:0 0 8px;font-size:13px;color:#94a3b8;">Or copy this link:</p>
  <p style="margin:0 0 32px;font-size:12px;font-family:monospace;color:#475569;background:#f1f5f9;padding:10px 14px;border-radius:6px;word-break:break-all;">${inviteUrl}</p>
  <hr style="border:none;border-top:1px solid #e2e8f0;margin:0 0 24px;" />
  <p style="margin:0;font-size:12px;color:#94a3b8;">This invitation was sent by FrostGate. If you didn't expect this, you can safely ignore it.</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;
}

function consoleInviteText(name: string, inviteUrl: string, tenantLabel: string) {
  return `Hi ${name},\n\nYou've been invited to access the FrostGate AI Governance Console for ${tenantLabel}.\n\nAccept your invitation (expires in 72 hours):\n${inviteUrl}\n\nIf you didn't expect this, you can safely ignore it.\n\n— FrostGate`;
}

// ─── Portal grant email ───────────────────────────────────────────────────────

function portalGrantHtml(
  name: string,
  loginUrl: string,
  password: string,
  portalRole: string,
  tenantLabel: string,
  expiresLabel: string,
) {
  const roleLabels: Record<string, string> = {
    executive: 'Executive — Risk posture & KPIs',
    remediation: 'Remediation — Findings with fix steps',
    technical: 'Technical — Full detail & evidence',
    compliance: 'Compliance — Framework mapping & posture',
    general: 'General — Full access',
  };
  const roleLabel = roleLabels[portalRole] ?? portalRole;

  return `<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;border:1px solid #e2e8f0;padding:40px;">
<tr><td>
  <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#0f172a;">Your FrostGate portal access is ready</p>
  <p style="margin:0 0 24px;font-size:14px;color:#64748b;">${tenantLabel}</p>
  <p style="margin:0 0 20px;font-size:15px;color:#334155;">Hi ${name},</p>
  <p style="margin:0 0 28px;font-size:15px;color:#334155;line-height:1.6;">
    You now have access to the <strong>FrostGate Governance Portal</strong> for <strong>${tenantLabel}</strong>.
    Your credentials are below — please save your password as it <strong>will not be shown again</strong>.
  </p>
  <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 28px;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
    <tr style="background:#f8fafc;">
      <td style="padding:12px 16px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:#64748b;width:130px;">Login URL</td>
      <td style="padding:12px 16px;font-size:13px;font-family:monospace;color:#1e40af;word-break:break-all;">${loginUrl}</td>
    </tr>
    <tr style="border-top:1px solid #e2e8f0;">
      <td style="padding:12px 16px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:#64748b;">Password</td>
      <td style="padding:12px 16px;font-size:13px;font-family:monospace;color:#0f172a;letter-spacing:0.05em;">${password}</td>
    </tr>
    <tr style="border-top:1px solid #e2e8f0;background:#f8fafc;">
      <td style="padding:12px 16px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:#64748b;">View type</td>
      <td style="padding:12px 16px;font-size:13px;color:#334155;">${roleLabel}</td>
    </tr>
    <tr style="border-top:1px solid #e2e8f0;">
      <td style="padding:12px 16px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:#64748b;">Access expires</td>
      <td style="padding:12px 16px;font-size:13px;color:#334155;">${expiresLabel}</td>
    </tr>
  </table>
  <p style="margin:0 0 28px;">
    <a href="${loginUrl}" style="display:inline-block;padding:12px 28px;background:#2563eb;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;font-size:15px;">Open portal</a>
  </p>
  <hr style="border:none;border-top:1px solid #e2e8f0;margin:0 0 24px;" />
  <p style="margin:0;font-size:12px;color:#94a3b8;">This access was provisioned by FrostGate. Contact your account manager with any questions.</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;
}

function portalGrantText(
  name: string,
  loginUrl: string,
  password: string,
  portalRole: string,
  tenantLabel: string,
  expiresLabel: string,
) {
  return `Hi ${name},\n\nYour FrostGate Governance Portal access for ${tenantLabel} is ready.\n\nLogin URL: ${loginUrl}\nPassword:  ${password}\nView type: ${portalRole}\nExpires:   ${expiresLabel}\n\nSave your password — it will not be shown again.\n\n— FrostGate`;
}

// ─── Route handler ────────────────────────────────────────────────────────────

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let body: Record<string, string>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  const { type } = body;

  try {
    if (type === 'console_invite') {
      const { to, name, invitation_url, tenant_label } = body;
      if (!to || !name || !invitation_url) {
        return NextResponse.json({ error: 'Missing required fields: to, name, invitation_url' }, { status: 422 });
      }
      const inviteUrl = `${CONSOLE_ORIGIN}${invitation_url}`;
      const label = tenant_label || 'your workspace';
      await sendMail({
        to,
        subject: `You've been invited to FrostGate — ${label}`,
        html: consoleInviteHtml(name, inviteUrl, label),
        text: consoleInviteText(name, inviteUrl, label),
      });
      return NextResponse.json({ sent: true });
    }

    if (type === 'portal_grant') {
      const { to, name, portal_login_url, raw_secret, portal_role, tenant_label, expires_at } = body;
      if (!to || !name || !portal_login_url || !raw_secret) {
        return NextResponse.json({ error: 'Missing required fields: to, name, portal_login_url, raw_secret' }, { status: 422 });
      }
      const loginUrl = portal_login_url.startsWith('http')
        ? portal_login_url
        : `${PORTAL_ORIGIN}${portal_login_url}`;
      const label = tenant_label || 'your engagement';
      const expiresLabel = expires_at
        ? new Date(expires_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
        : 'see portal';
      await sendMail({
        to,
        subject: `Your FrostGate portal access — ${label}`,
        html: portalGrantHtml(name, loginUrl, raw_secret, portal_role || 'general', label, expiresLabel),
        text: portalGrantText(name, loginUrl, raw_secret, portal_role || 'general', label, expiresLabel),
      });
      return NextResponse.json({ sent: true });
    }

    return NextResponse.json({ error: `Unknown email type: ${type}` }, { status: 422 });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    return NextResponse.json({ error: `Failed to send email: ${msg}` }, { status: 500 });
  }
}
