# X.509 Provisioning Lab — 日本語ガイド

開発・結合試験で使う**ローカルX.509証明書発行ツール**です。暗号化されたCA秘密鍵・主体の秘密鍵の生成、CSR作成、X.509 v3証明書の発行、模擬インストール、検証、失効模擬に対応します。

**試験専用**です。公的に信頼される認証局でも、本番の鍵管理基盤でもありません。

## 推奨実行（Windows / Python 3.13）

展開したフォルダでPowerShellを開きます。

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_tests.py
.\.venv\Scripts\python.exe run_x509lab.py demo --root example
.\.venv\Scripts\python.exe run_x509lab.py verify-demo --root example
explorer.exe .\artifacts\example
```

`demo`実行時にはCA用と主体秘密鍵用の**別々のパスフレーズ**を入力します。検証時は主体秘密鍵用の値を入力してください。

## 任意の主体の証明書を作成

```powershell
$py = '.\.venv\Scripts\python.exe'
& $py run_x509lab.py init-ca --root sample
& $py run_x509lab.py new-identity --root sample --subject-id application-a
& $py run_x509lab.py issue --root sample --subject-id application-a
& $py run_x509lab.py provision --root sample --subject-id application-a
& $py run_x509lab.py verify --root sample --subject-id application-a
```

すべての出力は `artifacts/sample/` 以下です。生成した秘密鍵の暗号化だけでは、共有・公開してよいという意味にはなりません。フォルダ全体をGit管理・ZIP配布しないでください。

## 注意事項

- 暗号処理は実際に行いますが、証明書チェーンの一般的な完全検証器ではありません。
- 失効はローカルの拒否リストで再現し、CRL/OCSPは提供しません。
- 対象証明書はテスト用のURI型SANです。一般的なWebサーバー用のDNS SANは生成しません。
- P-256 / ECDSA-SHA256、`clientAuth` と `serverAuth` の両EKUを用いる固定の試験用プロファイルです。
- ソースだけの再配布は `python scripts/package_source.py` を使用します。`artifacts/`を配布ZIPに含めません。

英語の[README](README.md)と[セキュリティ上の注意](SECURITY.md)も参照してください。
