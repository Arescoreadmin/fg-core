export async function GET() {
  return Response.json({ status: "ok" });
}

export async function HEAD() {
  return new Response(null, { status: 200 });
}
