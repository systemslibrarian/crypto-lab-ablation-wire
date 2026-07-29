# web/

Static demo root. Everything here is served by GitHub Pages as-is.

- `index.html` — the ablation console
- `pkg/`       — wasm-pack output, generated, not committed
- `.nojekyll`  — committed; see the deploy job for why it matters

Nothing in this directory needs a server-side anything, but it does need an
HTTP origin: ES modules and `WebAssembly.instantiateStreaming` both refuse to
load over `file://`.

```sh
wasm-pack build codetalker-wasm --target web --release --out-dir ../web/pkg
python3 -m http.server -d web 8080
```

Then open <http://localhost:8080>. With `pkg/` absent the page says so and
prints those two commands rather than failing blank — every number it displays
comes back from the WebAssembly module, so there is genuinely nothing to render
without it.

`.nojekyll` matters because Pages otherwise runs the site through Jekyll, which
silently drops any file or directory beginning with an underscore. wasm-pack
emits several. It is committed here as well as touched by the deploy job, so a
manual push cannot miss it.
