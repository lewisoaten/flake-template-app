# Third-party notices

This project uses two JavaScript libraries in the browser. **Neither is
committed to this repository.** They are declared in `package.json`, installed
by `npm ci` against the integrity hashes in `package-lock.json`, and copied into
`src/app/static/vendor/` (which is gitignored) by `just vendor`, run
automatically as part of `just setup`.

So this repository redistributes nothing, and these notices do not bind it.
They matter the moment *you* ship the frontend — a container image, a static
bundle, a tarball — because that is redistribution. Both upstreams publish
minified files with no license header, so nothing in the shipped bytes carries
the notice on its own:

- **htmx is 0BSD**, which imposes no conditions at all. Nothing to do.
- **Alpine is MIT**, which requires its copyright and permission notice to
  accompany any copy. If you distribute a build containing
  `alpine-csp.min.js`, include the Alpine notice below — shipping this file
  alongside it is the simplest way.

Python dependencies are resolved from PyPI at install time and are likewise not
redistributed by this repository; run `uv tree` to see them and their licenses.
Note that a container image built from the `Dockerfile` *does* contain them.

---

## htmx (`src/app/static/vendor/htmx.min.js`)

htmx 2.0.10 — https://htmx.org — © Big Sky Software

Licensed under the **Zero-Clause BSD** license, which imposes no conditions at
all; this notice is courtesy, not obligation.

```
Zero-Clause BSD
=============

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

---

## Alpine.js CSP build (`src/app/static/vendor/alpine-csp.min.js`)

`@alpinejs/csp` 3.16.1 — https://alpinejs.dev

Licensed under the **MIT** license. Retaining the notice below is a condition of
redistribution.

```
MIT License

Copyright © 2019-2025 Caleb Porzio and contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

Dependabot proposes upgrades to both automatically. When one lands, re-check the
upstream licence — a change of licence between versions is exactly the thing
that is easy to miss — and update this file.
