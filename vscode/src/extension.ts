import * as vscode from "vscode";
import {
    CloseAction,
    ErrorAction,
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel | undefined;
let fileWatcher: vscode.FileSystemWatcher | undefined;
let extensionContext: vscode.ExtensionContext | undefined;

// How many times the client may auto-restart the server after an
// unexpected close before it gives up. This guards against an aggressive
// restart loop when the configured command is fundamentally broken (for
// example a missing dependency or a wrong interpreter).
const MAX_RESTARTS = 4;

// Substring the server prints to stderr when pygls is not installed. See
// capa/lsp/server.py: serve() prints this and exits with code 2.
const PYGLS_HINT = "pygls is required";

interface ServerConfig {
    enabled: boolean;
    command: string[];
    capaPath: string[];
}

function readConfig(): ServerConfig {
    const cfg = vscode.workspace.getConfiguration("capa.languageServer");
    const command = cfg.get<string[]>("command", ["python", "-m", "capa", "lsp"]);
    const capaPath = cfg.get<string[]>("capaPath", []);
    return {
        enabled: cfg.get<boolean>("enabled", true),
        command: Array.isArray(command) ? command : [],
        capaPath: Array.isArray(capaPath) ? capaPath : [],
    };
}

function getOutputChannel(): vscode.OutputChannel {
    if (!outputChannel) {
        outputChannel = vscode.window.createOutputChannel("Capa Language Server");
        // Dispose the channel when the extension deactivates. The channel is
        // created lazily, so register it here rather than in activate().
        extensionContext?.subscriptions.push(outputChannel);
    }
    return outputChannel;
}

function getFileWatcher(): vscode.FileSystemWatcher {
    if (!fileWatcher) {
        fileWatcher = vscode.workspace.createFileSystemWatcher("**/*.capa");
        // Created lazily and shared across client restarts; dispose it on
        // deactivation via context.subscriptions.
        extensionContext?.subscriptions.push(fileWatcher);
    }
    return fileWatcher;
}

function pathDelimiter(): string {
    return process.platform === "win32" ? ";" : ":";
}

function buildEnv(config: ServerConfig): NodeJS.ProcessEnv {
    const env = { ...process.env };
    if (config.capaPath.length > 0) {
        const existing = env.CAPA_PATH ? [env.CAPA_PATH] : [];
        env.CAPA_PATH = [...config.capaPath, ...existing].join(pathDelimiter());
    }
    return env;
}

// Tracks why the server stopped, so the close handler can give a
// specific message and avoid redundant pop-ups.
interface RestartState {
    restarts: number;
    pyglsReported: boolean;
    sawPyglsHint: boolean;
    gaveUp: boolean;
}

async function startClient(config: ServerConfig): Promise<void> {
    if (config.command.length === 0) {
        await vscode.window.showErrorMessage(
            "Capa: the language server command is empty. Set " +
                "\"capa.languageServer.command\" to a valid argument vector, " +
                "for example [\"python\", \"-m\", \"capa\", \"lsp\"]."
        );
        return;
    }

    const [executable, ...args] = config.command;
    const channel = getOutputChannel();

    const serverOptions: ServerOptions = {
        command: executable,
        args,
        options: {
            env: buildEnv(config),
        },
    };

    const state: RestartState = {
        restarts: 0,
        pyglsReported: false,
        sawPyglsHint: false,
        gaveUp: false,
    };

    const clientOptions: LanguageClientOptions = {
        documentSelector: [{ scheme: "file", language: "capa" }],
        outputChannel: channel,
        synchronize: {
            // Reuse a single watcher owned by the extension and disposed on
            // deactivation. Creating a fresh watcher here would leak one
            // orphaned watcher on every client restart, because the library
            // only disposes the listeners it attaches to a watcher instance,
            // not the watcher itself.
            fileEvents: getFileWatcher(),
        },
        errorHandler: {
            error: () => ({ action: ErrorAction.Continue }),
            closed: () => {
                state.restarts += 1;
                if (state.sawPyglsHint && !state.pyglsReported) {
                    state.pyglsReported = true;
                    void offerPyglsHelp();
                    return { action: CloseAction.DoNotRestart, handled: true };
                }
                if (state.restarts > MAX_RESTARTS) {
                    state.gaveUp = true;
                    void reportGaveUp(executable, state.pyglsReported);
                    return { action: CloseAction.DoNotRestart, handled: true };
                }
                return { action: CloseAction.Restart };
            },
        },
    };

    const current = new LanguageClient(
        "capaLanguageServer",
        "Capa Language Server",
        serverOptions,
        clientOptions
    );
    client = current;

    // The library pipes the server's stderr into the output channel. We
    // watch the launched child process directly so we can spot the pygls
    // exit (code 2) and the hint it prints, even on the very first launch
    // where it exits before initialize completes.
    watchChildProcess(current, state, executable);

    try {
        await current.start();
        channel.appendLine(
            `Capa language server started: ${executable} ${args.join(" ")}`
        );
    } catch (err) {
        await handleStartFailure(err, executable, config, state);
    }
}

// vscode-languageclient does not expose the child process or its exit
// code through a stable public API in 8.x. We attach to it best-effort:
// if the internal handle is reachable we listen for stderr and exit; if
// not, detection falls back to the start() rejection and close handler.
function watchChildProcess(
    languageClient: LanguageClient,
    state: RestartState,
    executable: string
): void {
    const anyClient = languageClient as unknown as {
        _serverProcess?: {
            stderr?: { on(event: "data", cb: (chunk: Buffer) => void): void };
            on(event: "exit", cb: (code: number | null) => void): void;
        };
    };
    // The handle may not exist yet at this point; poll briefly.
    let attempts = 0;
    const timer = setInterval(() => {
        attempts += 1;
        const proc = anyClient._serverProcess;
        if (proc) {
            clearInterval(timer);
            proc.stderr?.on("data", (chunk) => {
                if (chunk.toString().includes(PYGLS_HINT)) {
                    state.sawPyglsHint = true;
                }
            });
            proc.on("exit", (code) => {
                if (code === 2) {
                    state.sawPyglsHint = true;
                }
                getOutputChannel().appendLine(
                    `Capa language server process exited (code ${code ?? "null"}).`
                );
            });
        } else if (attempts > 20) {
            clearInterval(timer);
        }
    }, 100);
}

async function handleStartFailure(
    err: unknown,
    executable: string,
    config: ServerConfig,
    state: RestartState
): Promise<void> {
    const channel = getOutputChannel();
    channel.appendLine(`Capa language server failed to start: ${String(err)}`);

    if (state.sawPyglsHint || isPyglsExit(err)) {
        if (!state.pyglsReported) {
            state.pyglsReported = true;
            await offerPyglsHelp();
        }
        return;
    }

    if (isSpawnFailure(err)) {
        const cmd = config.command.join(" ");
        const choice = await vscode.window.showWarningMessage(
            `Capa: could not launch the language server (\"${cmd}\"). The ` +
                `executable \"${executable}\" was not found. Syntax ` +
                "highlighting, snippets, and indentation still work. Install " +
                "Python >=3.10 with `pip install \"capa[lsp]\"`, or set " +
                "\"capa.languageServer.command\" to the right interpreter " +
                "(for example python3).",
            "Open Settings",
            "Show Output"
        );
        if (choice === "Open Settings") {
            await vscode.commands.executeCommand(
                "workbench.action.openSettings",
                "capa.languageServer.command"
            );
        } else if (choice === "Show Output") {
            channel.show(true);
        }
        return;
    }

    const choice = await vscode.window.showWarningMessage(
        "Capa: the language server failed to start. Syntax highlighting, " +
            "snippets, and indentation still work.",
        "Show Output"
    );
    if (choice === "Show Output") {
        channel.show(true);
    }
}

function isPyglsExit(err: unknown): boolean {
    if (err && typeof err === "object" && "code" in err) {
        const code = (err as { code?: unknown }).code;
        if (code === 2 || code === "2") {
            return true;
        }
    }
    const text = err instanceof Error ? err.message : String(err);
    return text.includes(PYGLS_HINT) || /\bcode\s*2\b/.test(text);
}

function isSpawnFailure(err: unknown): boolean {
    if (err && typeof err === "object" && "code" in err) {
        const code = (err as { code?: unknown }).code;
        // ENOENT: executable not found on PATH. EACCES: not executable.
        return code === "ENOENT" || code === "EACCES";
    }
    const text = err instanceof Error ? err.message : String(err);
    return /ENOENT|spawn .* failed|not found/i.test(text);
}

async function offerPyglsHelp(): Promise<void> {
    const choice = await vscode.window.showWarningMessage(
        "Capa: the language server needs the `pygls` dependency, which is " +
            "not installed. Run `pip install \"capa[lsp]\"` (or " +
            "`pip install \"pygls>=2.0\"`) for the Python interpreter the " +
            "server runs on, then run \"Capa: Restart Language Server\". " +
            "Syntax highlighting, snippets, and indentation still work " +
            "without it.",
        "Copy install command",
        "Show Output"
    );
    if (choice === "Copy install command") {
        await vscode.env.clipboard.writeText('pip install "capa[lsp]"');
        void vscode.window.showInformationMessage('Copied: pip install "capa[lsp]"');
    } else if (choice === "Show Output") {
        getOutputChannel().show(true);
    }
}

async function reportGaveUp(
    executable: string,
    pyglsReported: boolean
): Promise<void> {
    if (pyglsReported) {
        return;
    }
    const choice = await vscode.window.showWarningMessage(
        `Capa: the language server (\"${executable}\") kept stopping and ` +
            "has been disabled for this session. Syntax highlighting, " +
            "snippets, and indentation still work. Run \"Capa: Restart " +
            "Language Server\" after fixing the cause.",
        "Show Output"
    );
    if (choice === "Show Output") {
        getOutputChannel().show(true);
    }
}

async function stopClient(): Promise<void> {
    if (!client) {
        return;
    }
    const current = client;
    client = undefined;
    try {
        await current.stop();
    } catch {
        // Already stopped or never fully started; ignore.
    }
}

async function restart(): Promise<void> {
    await stopClient();
    const config = readConfig();
    if (!config.enabled) {
        void vscode.window.showInformationMessage(
            "Capa: the language server is disabled " +
                "(\"capa.languageServer.enabled\" is false)."
        );
        return;
    }
    await startClient(config);
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    extensionContext = context;
    context.subscriptions.push(
        vscode.commands.registerCommand("capa.restartLanguageServer", () =>
            restart()
        ),
        vscode.commands.registerCommand("capa.showServerOutput", () =>
            getOutputChannel().show(true)
        ),
        vscode.workspace.onDidChangeConfiguration((event) => {
            if (
                event.affectsConfiguration("capa.languageServer.enabled") ||
                event.affectsConfiguration("capa.languageServer.command") ||
                event.affectsConfiguration("capa.languageServer.capaPath")
            ) {
                void restart();
            }
        })
    );

    const config = readConfig();
    if (config.enabled) {
        await startClient(config);
    }
}

export async function deactivate(): Promise<void> {
    await stopClient();
    // The output channel and file watcher are disposed via
    // context.subscriptions; drop our references so a later reactivation
    // starts clean.
    outputChannel = undefined;
    fileWatcher = undefined;
    extensionContext = undefined;
}
