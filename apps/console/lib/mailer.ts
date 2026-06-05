import nodemailer from 'nodemailer';

const FROM_ADDRESS =
  process.env.SMTP_FROM || process.env.SMTP_USER || 'jason@frostgate.ai';

function createTransport() {
  const host = process.env.SMTP_HOST || 'smtp.office365.com';
  const port = parseInt(process.env.SMTP_PORT || '587', 10);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!user || !pass) {
    throw new Error('SMTP_USER and SMTP_PASS must be set to send email.');
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: false, // STARTTLS on 587
    auth: { user, pass },
    tls: { ciphers: 'SSLv3' },
  });
}

export interface MailOptions {
  to: string;
  subject: string;
  html: string;
  text: string;
}

export async function sendMail(opts: MailOptions) {
  const transport = createTransport();
  await transport.sendMail({
    from: `"FrostGate" <${FROM_ADDRESS}>`,
    to: opts.to,
    subject: opts.subject,
    html: opts.html,
    text: opts.text,
  });
}
