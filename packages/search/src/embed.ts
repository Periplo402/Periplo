/**
 * Embedding pipeline (spec Phase 5): fastembed's `BGESmallENV15`, entirely
 * local, no API key, no per-call cost, no external service dependency for
 * the CI gate to hold a secret for.
 *
 * Not `@huggingface/transformers`: that package hard-depends on `sharp` for
 * its vision-model utilities we don't use, and `sharp`'s prebuilt `libvips`
 * binary (`@img/sharp-libvips-linux-x64`) is LGPL-3.0, a hard deny under
 * `packages/licence-check`'s own policy (spec §1: no copyleft anywhere in
 * the shipped dependency path), not a borderline call to special-case.
 * `fastembed` resolves clean (MIT throughout, verified with
 * `license-checker` before adopting it) and ships a purpose-built
 * query/passage asymmetric-retrieval API (`queryEmbed`/`passageEmbed`) that
 * BGE-family models expect: the query side gets an internal
 * retrieval-instruction prefix the passage side doesn't, which a naive
 * "just call embed() for everything" approach would silently skip.
 *
 * Pinned at `2.1.1`, not the `2.1.0` this project shipped with originally:
 * `2.1.0` downloaded its model from a Google Cloud Storage bucket
 * (`storage.googleapis.com/qdrant-fastembed`) that started returning
 * `403 AccessDenied` for anonymous reads, breaking every CI run on a cache
 * miss (`TAR_BAD_ARCHIVE`, the GCS error body being un-tarred as if it were
 * the model). `2.1.1` downloads individual files from Hugging Face
 * directly instead, which also dropped the `tar` dependency entirely, see
 * `docs/DEFERRED.md` for the full history (including the now-resolved
 * `tar@^6.2.0` advisory this project previously accepted as a risk here).
 */

import { tmpdir } from "node:os";
import { join } from "node:path";
import { EmbeddingModel, FlagEmbedding } from "fastembed";

export const EMBEDDING_DIMENSIONS = 384;

/**
 * fastembed's own default (`cacheDir` unset) is `./local_cache` relative to
 * `process.cwd()`: inside the repo working directory when run locally or
 * in CI. Found live: the downloaded model landed in the repo root as an
 * untracked ~128MB directory, and Biome tried to lint the model's own
 * `config.json` as project source. Pinned outside the repo entirely so
 * this can't recur regardless of cwd.
 */
const CACHE_DIR = join(tmpdir(), "periplo-fastembed-cache");

let modelPromise: Promise<FlagEmbedding> | null = null;

/** Lazily initializes (and caches) the model. Downloads on first use, into CACHE_DIR. */
function getModel(): Promise<FlagEmbedding> {
  if (!modelPromise) {
    modelPromise = FlagEmbedding.init({
      model: EmbeddingModel.BGESmallENV15,
      cacheDir: CACHE_DIR,
    });
  }
  return modelPromise;
}

/**
 * Embeds catalog-side text (a resource's description + parameter schema),
 * the "passage" side of BGE's asymmetric retrieval API.
 *
 * `Array.from(...)` was load-bearing under `fastembed@2.1.0`, not defensive
 * styling: its `.d.ts` declared `number[]`, but at runtime both
 * `passageEmbed` and `queryEmbed` returned `Float32Array`:
 * `JSON.stringify(Float32Array)` serializes as `{"0":v0,"1":v1,...}`, not
 * `[v0,v1,...]`, which Postgres's `vector` column type rejects outright
 * ("invalid input syntax for type vector"). Verified empirically against
 * `fastembed@2.1.1` (the pinned version since) that this no longer
 * happens, both methods now return a plain `Array`; `Array.from` is kept
 * as a defensive no-op rather than removed, since the `.d.ts` claim it
 * guards against was already wrong once.
 */
export async function embedDocument(text: string): Promise<number[]> {
  const model = await getModel();
  for await (const batch of model.passageEmbed([text], 1)) {
    const vector = batch[0];
    if (!vector) {
      throw new Error("fastembed passageEmbed returned an empty batch");
    }
    return Array.from(vector);
  }
  throw new Error("fastembed passageEmbed produced no output");
}

/**
 * Embeds a search query: the "query" side of BGE's asymmetric retrieval
 * API. Not interchangeable with `embedDocument`: BGE models are trained
 * with a different instruction prefix on this side, applied internally by
 * `queryEmbed`. Same `Array.from` requirement as `embedDocument`, see its
 * doc comment.
 */
export async function embedQuery(text: string): Promise<number[]> {
  const model = await getModel();
  return Array.from(await model.queryEmbed(text));
}
