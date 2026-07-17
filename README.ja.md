# WG

[简体中文](./README.md) · [English](./README.en.md) · **日本語**

> サーバー IP を指定し、分流結果を管理しながら、システム DNS は変更しない——WG が目指すプライベートトンネル体験です。

[WG](https://github.com/Aiweline/WG) は、Go で開発されている軽量なインテリジェント・スプリットトンネリングプロジェクトです。クライアントにはグラフィカル UI を用意し、サーバーはスクリプトとコマンドラインで管理します。ドメイン、IP、CIDR の判定は後から変更でき、手動上書きを削除すると <code>AUTO</code> の自動分類へ戻ります。

> [!WARNING]
> **このリポジトリは安全な開発用ベースラインであり、本番利用可能な VPN ではありません。**  
> 現在は UDP データチャネル、TUN デバイス、システムルート、ファイアウォール、NAT を作成せず、実トラフィックも転送しません。「サーバー IP を入力して接続」は目標操作であり、現行ビルドはプロトコル部品、制御プレーン、クライアント UI、安全境界の検証を目的としています。

## 主な考え方

- **インテリジェント分流** — <code>AUTO</code> による自動判定と、<code>TUNNEL</code>、<code>DIRECT</code>、<code>BLOCK</code> の明示指定。
- **管理できる判定結果** — ドメイン、IP、CIDR の上書きを追加でき、削除後は自動分類に戻ります。
- **プライベート DNS コピー** — システムのリゾルバー設定を変更せず読み取り、独立した generation と専用 TTL キャッシュで扱います。
- **クライアント UI、スクリプト型サーバー** — クライアントは接続、分流、DNS、ヘルス、ペアリングを表示し、サーバーには UI がありません。
- **安全な開発を優先** — 管理リスナーはループバックに限定され、本番ネットワークモードは明示的に拒否されます。

<code>WG/1</code> と <code>WG-HS/1</code> はプロジェクト固有の実験的な形式と状態機械であり、**WireGuard 互換性を示すものではありません**。暗号機能には Go 実装の X25519、ChaCha20-Poly1305、BLAKE2s、HKDF を使用します。WG は独自の低レベル暗号プリミティブを作成しておらず、独立したセキュリティ監査もまだ受けていません。

## 現在実装されている機能

| モジュール | 安全開発版の機能 |
| --- | --- |
| <code>internal/codec</code> | 制限付き <code>WG/1</code> パケット、TLV、内部フレームの解析とシリアライズ。単体テストと fuzz エントリを含む |
| <code>internal/crypto</code> | 標準暗号プリミティブ、正規化指紋、ハンドシェイク/転送の高レベル API |
| <code>internal/handshake</code> | 登録済みクライアント向けのメモリ内 <code>WG-HS/1</code> 開発パス |
| <code>internal/session</code> | クライアント/サーバー状態機械、パケット番号、リプレイ防止 |
| <code>internal/routing</code> | ドメイン、IP、CIDR と 4 種類の分流判定 |
| <code>internal/privatedns</code> | リゾルバーの読み取り専用スナップショット、generation 分離、専用 TTL キャッシュ |
| <code>internal/controlapi</code> | サイズ、タイムアウト、同時実行数を制限したローカル管理 API |
| <code>cmd</code> / <code>ui</code> / <code>scripts</code> | 安全 core、5 画面のクライアント UI、dry-run 開発スクリプト |

これらはアーキテクチャと管理フローを検証するための機能であり、実際のトンネル通信はまだ処理しません。

## アーキテクチャ

~~~text
クライアント UI（React、Go ホストで配信）
        │  http://127.0.0.1:4173
        ▼
wg-client-ui
        │  /api/v1
        ▼
wg-core client（ループバック管理 API）
        ├── WG/1 + WG-HS/1
        ├── crypto + session
        ├── AUTO インテリジェント分流
        └── プライベート DNS スナップショット/キャッシュ

wg-core server（UI なし、スクリプト管理）
        └── 安全モードではデータアドレス設定を記録するだけ

UDP / TUN / システムルート / ファイアウォール / NAT
        └── 未接続
~~~

## クライアント UI

![WG クライアント接続ページのプロトタイプ](./docs/ui-prototypes/wg-client-01-connection.png)

クライアントには「接続」「インテリジェント分流」「プライベート DNS」「ヘルスと更新」「初回ペアリング」の 5 画面があります。その他のプロトタイプは [docs/ui-prototypes](./docs/ui-prototypes) にあります。

## 必要環境

- Go 1.26+
- Node.js 20+
- <code>make</code>

## クイックスタート

~~~sh
git clone https://github.com/Aiweline/WG.git
cd WG
npm --prefix ui/client install
make build
~~~

安全開発クライアント core を起動します。

~~~sh
WG_DEV_SAFE=1 ./bin/wg-core client \
  --dev-safe \
  --no-host-network \
  --management-address 127.0.0.1:47003 \
  --endpoint 203.0.113.10:47001
~~~

<code>203.0.113.10</code> は TEST-NET の文書用アドレスです。現行ビルドはエンドポイントを記録するだけで、実トンネルを確立しません。

別のターミナルでクライアント UI を起動します。

~~~sh
./bin/wg-client-ui \
  --listen 127.0.0.1:4173 \
  --assets ui/client/dist \
  --core http://127.0.0.1:47003
~~~

[http://127.0.0.1:4173/](http://127.0.0.1:4173/) を開きます。

任意で安全開発サーバー core を起動できます。

~~~sh
WG_DEV_SAFE=1 ./bin/wg-core server \
  --dev-safe \
  --no-host-network \
  --management-address 127.0.0.1:47002 \
  --listen 0.0.0.0:47001
~~~

安全モードの <code>--listen</code> は設定値を記録するだけで、UDP ソケットは開きません。

## WG スクリプト

次のコマンドは、それぞれ独立した dry-run の例です。

~~~sh
./scripts/wg-server install 203.0.113.10 --dry-run

./scripts/wg-server pair \
  --output ./wg-pairing.wgp \
  --expires 10m \
  --dry-run

./scripts/wg-client install \
  203.0.113.10 \
  ./wg-pairing.wgp \
  --dry-run
~~~

> [!IMPORTANT]
> dry-run でペアリングファイルが作成されるとは限りません。実インストールは未完成で、<code>install --execute</code> は意図的に失敗します。本番の導入手順として扱わないでください。

## リポジトリ構成

~~~text
cmd/                    wg-core と wg-client-ui
internal/               プロトコル、セッション、分流、DNS、制御 API
scripts/                wg-client と wg-server
ui/client/              クライアント UI
docs/ui-prototypes/     複数画面のプロトタイプ
tests/                  パッケージ横断/境界テスト
~~~

## 検証

~~~sh
go test ./cmd/... ./internal/... ./tests/...
go test -race ./cmd/... ./internal/... ./tests/...
go vet ./cmd/... ./internal/... ./tests/...
npm --prefix ui/client run build
sh -n scripts/wg-client
sh -n scripts/wg-server
~~~

## 本番利用前に必要な作業

- UDP 転送、実 TUN データプレーン、IPv4/IPv6、MTU、通信暗号化の統合。
- 原子的ルート処理、最小権限ヘルパー、サービス分離、ファイアウォール/NAT、失敗時ロールバック。
- 完全なプライベート DNS socket、リンク単位のリゾルバー取得、TTL 更新。
- 永続クライアント登録、本番用鍵ライフサイクル、ワンタイム登録、RETRY 状態。
- 署名付きリリース、サプライチェーン検証、パッケージ化、クロスプラットフォーム試験、独立セキュリティ監査。

## コントリビューション

Issue と Pull Request を歓迎します。安全開発モードを既定値として維持し、動作変更にはテストを追加し、提出前にすべての検証コマンドを実行してください。

プロトコル、暗号、リプレイ防止、分流、DNS、システムネットワークを変更する場合は、互換性、セキュリティ影響、検証根拠を Pull Request に記載してください。

