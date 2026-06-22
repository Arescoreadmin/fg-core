import { Resend } from 'resend';

const FROM_ADDRESS =
  process.env.RESEND_FROM || 'FrostGate <noreply@frostgate.ai>';

function client() {
  const key = process.env.RESEND_API_KEY;
  if (!key) throw new Error('RESEND_API_KEY is not set.');
  return new Resend(key);
}

export interface MailOptions {
  to: string;
  subject: string;
  html: string;
  text: string;
}

export async function sendMail(opts: MailOptions) {
  const { error } = await client().emails.send({
    from: FROM_ADDRESS,
    to: [opts.to],
    subject: opts.subject,
    html: opts.html,
    text: opts.text,
  });
  if (error) throw new Error(error.message);
}
