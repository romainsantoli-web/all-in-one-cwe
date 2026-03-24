// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { listScans } from "@/lib/data";

export const dynamic = "force-dynamic";

export async function GET() {
  const files = await listScans();
  return NextResponse.json(files);
}
