// Command kh-app is the desktop half of kilhook: a Wails v3 window over the
// same engine cmd/kh-cli uses. Nothing here reimplements the loop — it binds
// internal/engine to a Svelte frontend and renders internal/report's JSON.
package main

import (
	"embed"
	"log"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var appIcon []byte

const (
	defaultWidth  = 1280
	defaultHeight = 820
)

func main() {
	app := application.New(application.Options{
		Name:        "kilhook",
		Description: "Local-first API workbench",
		Icon:        appIcon,
		Services: []application.Service{
			application.NewService(NewWorkspace()),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})

	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:     "kilhook",
		Width:     defaultWidth,
		Height:    defaultHeight,
		MinWidth:  900,
		MinHeight: 520,
		// The app paints its own titlebar: the topbar is a caption drag
		// region (-webkit-app-region: drag; --wails-draggable: drag) and the
		// window buttons are DOM elements calling the runtime. Native
		// hit-testing needs WebView2's non-client region support on Windows.
		Frameless:        true,
		BackgroundColour: application.NewRGB(9, 11, 17),
		Windows: application.WindowsWindow{
			NonClientRegionSupport: true,
		},
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 42,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		URL: "/",
	})

	// The default 1280x820 is logical pixels. On a 125%-scaled 1366x768 or
	// 1536x864 display that is physically larger than the screen, so the right
	// edge (including the window buttons) is clipped. Fit the window to the
	// primary work area once screens are known; Windows only populates the
	// ScreenManager during startup, not before app.Run.
	var fitOnce sync.Once
	win.OnWindowEvent(events.Common.WindowShow, func(*application.WindowEvent) {
		fitOnce.Do(func() { fitWindowToScreen(app, win) })
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

func fitWindowToScreen(app *application.App, win *application.WebviewWindow) {
	primary := app.Screen.GetPrimary()
	if primary == nil {
		return
	}
	w, h := defaultWidth, defaultHeight
	if maxW := primary.WorkArea.Width - 32; maxW > 0 && w > maxW {
		w = maxW
	}
	if maxH := primary.WorkArea.Height - 32; maxH > 0 && h > maxH {
		h = maxH
	}
	// Never shrink below the window's declared minimum.
	if w < 900 {
		w = 900
	}
	if h < 520 {
		h = 520
	}
	if w == defaultWidth && h == defaultHeight {
		return
	}
	win.SetSize(w, h)
	win.Center()
}
