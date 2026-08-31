# Sites deployment policy

The public site is hosted through OpenAI Sites with Cloudflare serving the custom domain. The canonical public content lives in `site/`. Sites can serve matching public HTML files before its Worker, so deployment staging moves all HTML documents into the Worker bundle. That keeps routing and response policy under one tested code path.

Stage the canonical source into an existing Sites checkout that already has its own `.openai/hosting.json`:

```bash
python scripts/stage_sites_deployment.py --destination /path/to/sites-checkout
```

The staging command:

- copies HTML documents into `worker/documents/` for Vite to bundle as raw text;
- removes directly served HTML and `_redirects` files from `public/`;
- copies CSS, JavaScript, JSON, images, robots, sitemap, and `_headers` into `public/`; and
- installs the canonical Worker and Vite type reference;
- prepares the complete public and Worker trees before replacing either live tree;
- restores both prior trees if any installation step fails; and
- writes `.openai/remedialhq-staging-manifest.json` with the source commit,
  canonical digest, source file count, and Sites project ID.

The Worker:

- redirects `www.remedialhq.com` to the apex host;
- permanently redirects known `.html`, `/index`, and trailing-slash routes to clean URLs;
- serves every public document from the bundle with the full HTTPS response policy;
- preserves queries during canonical redirects;
- returns the branded 404 document with `no-store`;
- applies security headers to asset responses that reach the Worker; and
- rejects non-read methods.

The deployment checkout stores only the Sites project identifier in `.openai/hosting.json`. Credentials and temporary source-write grants stay outside this repository. Push the exact validated commit before saving a Sites version, package the successful build output, and deploy only that saved version.
