/** Links do autor e do repositório, definidos por variáveis de ambiente (vazio = item oculto). */

function safeUrl(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? url.toString() : null;
  } catch {
    return null;
  }
}

export const AUTHOR_NAME: string | null = process.env.NEXT_PUBLIC_AUTHOR_NAME?.trim() || null;
export const REPO_URL: string | null = safeUrl(process.env.NEXT_PUBLIC_REPO_URL);
export const LINKEDIN_URL: string | null = safeUrl(process.env.NEXT_PUBLIC_LINKEDIN_URL);
