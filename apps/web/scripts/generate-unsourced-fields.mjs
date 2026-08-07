/**
 * Write the product-facing inventory of fields the designed experience assumes and the platform
 * does not produce.
 *
 * The finding is a PRODUCT question, not a frontend one. The donor design promises
 * `Deployment.costToDate`, `InfraTarget.capacity`, `Team.subnet` and forty more; the control plane
 * measures none of them. Some are probably worth implementing backend-side, some are presentation
 * choices the platform should never own, and some describe a product concept that does not exist
 * yet — but that is a decision for whoever owns the product, and it cannot be made from a source
 * file nobody outside this slice reads.
 *
 * The rendering lives in `src/api/unsourced-fields-doc.ts` and is imported here. This file does
 * the I/O and nothing else, so importing the renderer cannot write the document — see the note
 * there for what happened when it could.
 *
 *   npm run generate:unsourced-fields
 */

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  renderAbsentEndpointsDoc,
  renderUnsourcedFieldsDoc,
} from "../src/api/unsourced-fields-doc.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const PRODUCT_DOCS = resolve(REPO_ROOT, "docs", "product");

await mkdir(PRODUCT_DOCS, { recursive: true });
for (const [name, render] of [
  ["unsourced-fields.md", renderUnsourcedFieldsDoc],
  ["absent-endpoints.md", renderAbsentEndpointsDoc],
]) {
  await writeFile(resolve(PRODUCT_DOCS, name), render(), "utf8");
  console.log(`wrote docs/product/${name}`);
}
