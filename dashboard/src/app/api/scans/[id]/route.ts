// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { loadScan, deleteScan, renameScan } from "@/lib/data";

export const dynamic = "force-dynamic";

type RouteCtx = { params: Promise<{ id: string }> };

export async function GET(_request: Request, { params }: RouteCtx) {
  const { id } = await params;
  const filename = decodeURIComponent(id);
  const report = await loadScan(filename);

  if (!report) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  return NextResponse.json(report);
}

export async function DELETE(_request: Request, { params }: RouteCtx) {
  const { id } = await params;
  const filename = decodeURIComponent(id);
  const ok = await deleteScan(filename);

  if (!ok) {
    return NextResponse.json({ error: "Delete failed" }, { status: 404 });
  }

  return NextResponse.json({ ok: true });
}

export async function PATCH(request: Request, { params }: RouteCtx) {
  const { id } = await params;
  const filename = decodeURIComponent(id);

  let body: { newName?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (!body.newName || typeof body.newName !== "string") {
    return NextResponse.json(
      { error: "Missing newName" },
      { status: 400 }
    );
  }

  const result = await renameScan(filename, body.newName);
  if (!result) {
    return NextResponse.json(
      { error: "Rename failed — invalid characters or file not found" },
      { status: 400 }
    );
  }

  return NextResponse.json({ ok: true, newName: result });
}
