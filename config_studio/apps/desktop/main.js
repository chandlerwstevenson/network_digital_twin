const { app, BrowserWindow, ipcMain, protocol, net } = require("electron");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

const ENGINE_PORT = 8000;
const isDev = !app.isPackaged;

let engineProcess = null;
let mainWindow = null;

/* ------------------------------------------------------------------ */
/*  Python engine lifecycle                                            */
/* ------------------------------------------------------------------ */

function getEnginePath() {
  if (isDev) {
    return path.join(__dirname, "..", "engine");
  }
  return path.join(process.resourcesPath, "engine");
}

function startEngine() {
  const engineDir = getEnginePath();
  const python = process.platform === "win32" ? "python" : "python3";

  engineProcess = spawn(
    python,
    ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", String(ENGINE_PORT)],
    {
      cwd: engineDir,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    }
  );

  engineProcess.stdout.on("data", (data) => {
    console.log(`[engine] ${data.toString().trim()}`);
  });

  engineProcess.stderr.on("data", (data) => {
    console.error(`[engine] ${data.toString().trim()}`);
  });

  engineProcess.on("error", (err) => {
    console.error("Failed to start engine:", err.message);
  });

  engineProcess.on("exit", (code) => {
    console.log(`Engine exited with code ${code}`);
    engineProcess = null;
  });
}

function stopEngine() {
  if (engineProcess) {
    engineProcess.kill();
    engineProcess = null;
  }
}

/* ------------------------------------------------------------------ */
/*  Wait for the engine to be ready                                    */
/* ------------------------------------------------------------------ */

async function waitForEngine(retries = 30, delay = 500) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${ENGINE_PORT}/docs`);
      if (res.ok || res.status === 200) return true;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, delay));
  }
  console.error("Engine did not start in time");
  return false;
}

/* ------------------------------------------------------------------ */
/*  Custom protocol for serving static files                           */
/* ------------------------------------------------------------------ */

const RENDERER_SCHEME = "app";

function getRendererPath() {
  if (isDev) {
    return path.join(__dirname, "..", "web", "out");
  }
  return path.join(__dirname, "renderer");
}

function registerProtocol() {
  protocol.handle(RENDERER_SCHEME, (request) => {
    const rendererDir = getRendererPath();
    let url = new URL(request.url);
    let filePath = decodeURIComponent(url.pathname);

    // Remove leading slash on Windows
    if (process.platform === "win32" && filePath.startsWith("/")) {
      filePath = filePath.slice(1);
    }

    // Default to index.html for root
    if (filePath === "/" || filePath === "") {
      filePath = "/index.html";
    }

    let fullPath = path.join(rendererDir, filePath);

    // If the path has no extension, try appending .html (Next.js static export)
    if (!path.extname(fullPath)) {
      const htmlPath = fullPath + ".html";
      if (fs.existsSync(htmlPath)) {
        fullPath = htmlPath;
      } else {
        // Try index.html inside the directory
        const indexPath = path.join(fullPath, "index.html");
        if (fs.existsSync(indexPath)) {
          fullPath = indexPath;
        }
      }
    }

    return net.fetch("file://" + fullPath);
  });
}

/* ------------------------------------------------------------------ */
/*  Window                                                             */
/* ------------------------------------------------------------------ */

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    title: "Optimesh Config Studio",
    titleBarStyle: "hiddenInset",
    trafficLightPosition: { x: 16, y: 18 },
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadURL(`${RENDERER_SCHEME}://renderer/`);

  if (isDev) {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

/* ------------------------------------------------------------------ */
/*  IPC                                                                */
/* ------------------------------------------------------------------ */

ipcMain.handle("get-engine-url", () => `http://127.0.0.1:${ENGINE_PORT}`);

/* ------------------------------------------------------------------ */
/*  App lifecycle                                                      */
/* ------------------------------------------------------------------ */

protocol.registerSchemesAsPrivileged([
  {
    scheme: RENDERER_SCHEME,
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: true,
    },
  },
]);

app.whenReady().then(async () => {
  registerProtocol();
  startEngine();
  await waitForEngine();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", () => {
  stopEngine();
});
