import { mount } from 'svelte'
import '@fontsource-variable/inter'
import App from './App.svelte'

// Surface runtime errors in the window: without a devtools console attached a
// thrown component just leaves the previous branch on screen, which looks like
// "the tab does nothing".
function showError(text: string) {
  const box = document.createElement('pre')
  box.style.cssText =
    'position:fixed;bottom:0;left:0;right:0;max-height:40%;overflow:auto;background:#3a1118;color:#ffd7d7;border-top:1px solid #7a2b36;padding:8px 12px;margin:0;font:11px/1.5 ui-monospace,monospace;white-space:pre-wrap;z-index:9999'
  box.textContent = text
  document.body.appendChild(box)
}

window.addEventListener('error', (event) => {
  showError('JS error: ' + (event.error?.stack ?? event.message))
})
window.addEventListener('unhandledrejection', (event) => {
  const reason = event.reason
  showError('Unhandled rejection: ' + (reason?.stack ?? String(reason)))
})

mount(App, { target: document.getElementById('app')! })
