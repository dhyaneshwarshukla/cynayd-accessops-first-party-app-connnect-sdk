// app/api/auth/one/[...operation]/route.ts
import { handle } from '@/server/one-host/config.cjs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const GET = handle;
export const POST = handle;
