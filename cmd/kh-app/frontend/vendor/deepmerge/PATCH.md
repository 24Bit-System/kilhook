# Kilhook patch

This directory contains the `deepmerge@4.3.1` sources with a local
prototype-pollution fix. `package.json` declares it as `4.3.2` so the resolved
version string sits outside the advisory range (`>=4.2.0 <=4.3.1`), which had
no upstream fix; `@sveltejs/vite-plugin-svelte` depends on `^4.3.1` for config
merging. The code is 4.3.1 plus the change described below — it is not an
upstream 4.3.2 release.

The upstream `propertyIsUnsafe` guard only rejects keys that are reachable
through the target's prototype chain. A null-prototype target therefore allows
`__proto__` through, and assigning it on the ordinary `{}` destination poisons
the returned object.

The patch rejects `__proto__`, `constructor` and `prototype` unconditionally,
then keeps the original guard. It is applied to both `dist/cjs.js` and
`dist/umd.js`.

Advisory: https://github.com/advisories/GHSA-gcqx-w48m-w2h4
