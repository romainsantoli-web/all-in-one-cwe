// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { loadScan } from "@/lib/data";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const filename = decodeURIComponent(id);
  const report = await loadScan(filename);

  if (!report) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  return NextResponse.json(report);
}
