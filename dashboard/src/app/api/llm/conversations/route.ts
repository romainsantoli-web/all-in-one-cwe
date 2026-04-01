// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { readdir, readFile, writeFile, unlink, mkdir } from "fs/promises";
import { join } from "path";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";
const CONVERSATIONS_DIR = join(PROJECT_ROOT, "reports", "llm-conversations");
const REPORTS_LLM_DIR = join(PROJECT_ROOT, "reports", "reports-llm");

const SAFE_ID = /^[a-zA-Z0-9_-]{1,64}$/;

async function ensureDirs() {
  await mkdir(CONVERSATIONS_DIR, { recursive: true });
  await mkdir(REPORTS_LLM_DIR, { recursive: true });
}

/** GET — list all conversations or get one by ?id= */
export async function GET(request: Request) {
  await ensureDirs();
  const { searchParams } = new URL(request.url);
  const id = searchParams.get("id");

  if (id) {
    if (!SAFE_ID.test(id)) {
      return NextResponse.json({ error: "Invalid id" }, { status: 400 });
    }
    try {
      const raw = await readFile(join(CONVERSATIONS_DIR, `${id}.json`), "utf-8");
      return NextResponse.json(JSON.parse(raw));
    } catch {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }
  }

  // List all
  try {
    const files = await readdir(CONVERSATIONS_DIR);
    const convos = await Promise.all(
      files
        .filter((f) => f.endsWith(".json"))
        .map(async (f) => {
          try {
            const raw = await readFile(join(CONVERSATIONS_DIR, f), "utf-8");
            const data = JSON.parse(raw);
            return {
              id: data.id,
              title: data.title || "Untitled",
              createdAt: data.createdAt,
              updatedAt: data.updatedAt,
              messageCount: data.messages?.length || 0,
              provider: data.provider || null,
              model: data.model || null,
            };
          } catch {
            return null;
          }
        })
    );
    const valid = convos.filter(Boolean).sort((a, b) =>
      new Date(b!.updatedAt).getTime() - new Date(a!.updatedAt).getTime()
    );
    return NextResponse.json({ conversations: valid });
  } catch {
    return NextResponse.json({ conversations: [] });
  }
}

/** POST — save a conversation */
export async function POST(request: Request) {
  await ensureDirs();
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const id = typeof body.id === "string" && SAFE_ID.test(body.id) ? body.id : null;
  if (!id) {
    return NextResponse.json({ error: "Invalid or missing id" }, { status: 400 });
  }

  // Save conversation
  const conversation = {
    id,
    title: typeof body.title === "string" ? body.title.slice(0, 200) : "Untitled",
    messages: Array.isArray(body.messages) ? body.messages : [],
    provider: typeof body.provider === "string" ? body.provider : null,
    model: typeof body.model === "string" ? body.model : null,
    createdAt: typeof body.createdAt === "string" ? body.createdAt : new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  await writeFile(
    join(CONVERSATIONS_DIR, `${id}.json`),
    JSON.stringify(conversation, null, 2),
    "utf-8"
  );

  // If there's a report to save, save it separately too
  if (typeof body.report === "string" && body.report.length > 0) {
    const reportFilename = `report-${id}-${Date.now()}.md`;
    await writeFile(
      join(REPORTS_LLM_DIR, reportFilename),
      body.report,
      "utf-8"
    );
  }

  return NextResponse.json({ ok: true, id });
}

/** DELETE — delete a conversation */
export async function DELETE(request: Request) {
  await ensureDirs();
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const id = typeof body.id === "string" && SAFE_ID.test(body.id) ? body.id : null;
  if (!id) {
    return NextResponse.json({ error: "Invalid or missing id" }, { status: 400 });
  }

  try {
    await unlink(join(CONVERSATIONS_DIR, `${id}.json`));
  } catch {
    // May not exist, fine
  }

  return NextResponse.json({ ok: true });
}
