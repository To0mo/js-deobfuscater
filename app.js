document.getElementById('runBtn').addEventListener('click', runDeobfuscator);
document.getElementById('clearBtn').addEventListener('click', () => {
    document.getElementById('inputCode').value = '';
    document.getElementById('outputCode').value = '';
    document.getElementById('logs').innerHTML = '';
});

function logMessage(msg) {
    const logs = document.getElementById('logs');
    const time = new Date().toLocaleTimeString();
    logs.innerHTML += `<div><span class="log-time">[${time}]</span> ${msg}</div>`;
    logs.scrollTop = logs.scrollHeight;
}

let sandboxIframe = null;

function runDeobfuscator() {
    const code = document.getElementById('inputCode').value;
    if (!code) return;

    // 前回のサンドボックスが残っていれば破棄（初期化）
    if (sandboxIframe) {
        document.body.removeChild(sandboxIframe);
    }

    logMessage("Sandbox initializing...");

    // サンドボックス用の iframe を作成
    sandboxIframe = document.createElement('iframe');
    sandboxIframe.style.display = 'none';
    document.body.appendChild(sandboxIframe);

    const sandboxWindow = sandboxIframe.contentWindow;

    // --- 1. eval と Function のフック ---
    const originalEval = sandboxWindow.eval;
    const originalFunction = sandboxWindow.Function;

    sandboxWindow.eval = function(evalCode) {
        logMessage("🔥 Intercepted via eval()");
        processAndOutput(evalCode);
        
        // 監視を続けるため、元のevalを実行して処理を進めさせる（マルウェア実行の危険がある場合はコメントアウトを検討）
        return originalEval.apply(this, arguments);
    };

    sandboxWindow.Function = function(...args) {
        logMessage("🔥 Intercepted via Function()");
        const fnCode = args[args.length - 1]; // Functionコンストラクタの最後の引数がコード本体
        processAndOutput(fnCode);
        
        return originalFunction.apply(this, arguments);
    };

    logMessage("Hooks injected. Executing target code...");

    // --- 2. サンドボックス内で難読化コードを実行 ---
    try {
        // iframe内にscriptタグを注入して実行させる
        const script = sandboxIframe.contentDocument.createElement('script');
        script.textContent = code;
        sandboxIframe.contentDocument.body.appendChild(script);
        logMessage("Initial execution complete. Monitoring for future eval/Function calls...");
    } catch (e) {
        logMessage(`❌ Execution Error: ${e.message}`);
    }
}

// --- 3. 抽出したコードの AST Deobfuscate ---
function processAndOutput(rawCode) {
    let processedCode = rawCode;
    
    try {
        logMessage("Starting AST transformations (String Chunks, Decodes)...");
        
        // Babelプラグインの定義
        const deobfuscatePlugin = function({ types: t }) {
            return {
                visitor: {
                    // 文字列のチャンク結合 ("a" + "b" => "ab")
                    BinaryExpression(path) {
                        if (path.node.operator === '+') {
                            const left = path.node.left;
                            const right = path.node.right;
                            if (t.isStringLiteral(left) && t.isStringLiteral(right)) {
                                path.replaceWith(t.stringLiteral(left.value + right.value));
                            }
                        }
                    },
                    // 簡易的な String Array アクセスの解決などはここに拡張可能
                    // （難読化ツール特有の関数パターンを解析して置換する処理等）
                }
            };
        };

        // Babelでコードを変換
        const output = Babel.transform(rawCode, {
            plugins: [deobfuscatePlugin],
            generatorOpts: {
                // jsescOption minimal: true によって \xXX や \uXXXX などのエスケープが解除された生文字になる
                jsescOption: { minimal: true } 
            }
        });

        processedCode = output.code;
        logMessage("AST transformations success.");
    } catch (e) {
        logMessage(`⚠️ AST Parsing Error (Might be invalid JS or deeply obfuscated): ${e.message}`);
    }

    // 出力エリアへ追記
    const outputArea = document.getElementById('outputCode');
    outputArea.value += "\n/* =========================================\n   Intercepted Payload \n   ========================================= */\n";
    outputArea.value += processedCode + "\n\n";
}
