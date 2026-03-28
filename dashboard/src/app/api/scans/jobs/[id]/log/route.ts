// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { readFile } from "fs/promises";
import { join } from "path";

export const dynamic = "force-dynamic";

function getJobsDir(): string {
  return join(process.env.PROJECT_ROOT || "/data", "reports", ".jobs");
}

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  // Prevent path traversal
  const safe = id.replace(/[^a-zA-Z0-9_-]/g, "");
  if (safe !== id) {
    return new NextResponse("Invalid id", { status: 400 });
  }
  try {
    const logPath = join(getJobsDir(), `${safe}.log`);
    const content = await readFile(logPath, "utf-8");
    return new NextResponse(content, {
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  } catch {
    return new NextResponse("", { status: 404 });
  }
}
