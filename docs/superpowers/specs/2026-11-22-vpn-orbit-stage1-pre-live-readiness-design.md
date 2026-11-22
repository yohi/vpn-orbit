# VPN-ORBIT — Stage 1 Pre-Live Readiness Design R0.1

**Status:** ADOPTED_BY_HUMAN_OWNER (design only; implementation and GitHub code writes not authorized)  
**Repository:** `yohi/vpn-orbit`  
**Baseline:** `master@7f1ae8cab84a94cea8369e8075b4982b652f1557`  
**Related:** Issue #9 / PR #8 (merged)  
**Selected Approach:** A — master限定補強

## 1. Goal

Stage 1の固定候補実通信を、安全かつ再現可能に実施するための機能を完成させ、Human Ownerの新規承認を待つ状態にする。

本設計の完成は、東京出口IPv4の実証成功を意味しない。

### Deliverables

1. 最新masterを基準にした必要最小限の安全検証補強
2. 固定候補IDによる1候補実行機能
3. 実行結果・中断状態・Cleanup証拠の記録
4. オフラインテストと回帰テストの結果
5. KVM実機検証用の最小Runbook

## 2. Approaches

**A. master限定補強 — 採択**

現行のProbeRunner、Supervisor、Isolation、Cleanupを維持し、不足している境界だけ実装する。KVMパッチは参考資料として使用し、機械的移植は行わない。

**B. KVMパッチ3本を移植 — 不採択**

既存の実装とテストを再利用しやすい反面、masterの変更と衝突する可能性がある。不要な差分の混入を避けるため採用しない。

## 3. Architecture

既存の `vpn_orbit.cloud_probe` による通常の候補探索は維持する。

固定候補検証用に、CLI境界として `vpn_orbit.stage1_fixed_probe` を追加する。

```text
Stage 1 Fixed CLI
    |
    +-- list: Catalog取得・候補識別
    |
    +-- probe-id: 固定ID照合
            |
            +-- Preflight
            +-- Attempt Journal予約
            +-- probe_one()（既存）
                  |
                  +-- Supervisor / Namespace
                  +-- OpenVPN / TUN
                  +-- nftables DROP証拠
                  +-- TUN HTTPS / GeoIP
                  +-- Cleanup
            |
            +-- Result Journal確定
            +-- Redacted JSON出力
```

既存Supervisorを置き換えたり、別のOpenVPN実行器を実装したりしない。

## 4. Fixed Candidate Contract

CLI:

- `python3 -m vpn_orbit.stage1_fixed_probe --list`
- `python3 -m vpn_orbit.stage1_fixed_probe --probe-id <ID>`

両モードは排他的とする。

候補IDは既存補助スクリプトとの互換性を維持する。

```python
sha256(
    f"{ip}:{port}/{protocol}\n".encode("ascii")
    + profile.encode("utf-8")
).hexdigest()
```

`--probe-id` はCatalogを再取得し、既存Stage 1の選別条件に従って候補を照合する。

- ID完全一致：対象候補を1件だけ選択
- ID不一致・プロファイル変更・候補消失：NOT_VERIFIED、OpenVPN起動禁止
- 重複一致・識別不整合：BLOCKED
- 別候補への切替・フォールバック：禁止

固定候補モードでは、既存のTCP事前疎通確認を使用しない。候補照合のためにVPNサーバーへ直接TCP接続しない。

Catalog取得・GeoIP照会と、隔離下のVPN実通信は明確に区別する。

## 5. DROP Evidence Contract

既存の `host_direct_route_rejected()` を限定補強する。

直接通信の拒否判定では、次の両方を必須とする。

1. vethに固定したHTTPS通信が拒否またはタイムアウトする。
2. 該当通信を拒否するNamespace内nftablesルールのDROPカウンターが増加する。

専用DROPルールは、指定されたecho IPv4・TCP/443・veth送信インターフェースに限定する。

カウンターは専用ルールの識別子で取得する。検証前後の値を同じルールについて比較し、パケット数が厳密に増加した場合だけ証拠成立とする。

次の場合はFAILとする。

- curlの拒否が確認できない
- DROPカウンターが増加しない
- カウンター取得・解析に失敗
- ルール識別に不整合がある
- 直接通信が成功した

`ip route get ... oif DEV` の成功・失敗は補助情報であり、遮断成功の根拠にしない。

既存のVPNサーバー宛通信許可、TUN経由HTTPS許可、DNS/IPv6遮断、TLS検証は緩和しない。

DROP証拠の成立前に東京出口IPv4のPASSを確定してはならない。

## 6. Attempt Journal Contract

固定候補の実行結果を回収できなかった問題を防ぐため、試行状態をローカルに記録する。

記録先はゲスト内のroot所有・アクセス制限された専用状態ディレクトリとし、Gitリポジトリ外に置く。

記録対象：

- attempt_id
- candidate_id
- ingressのIP・port・protocol
- 実行コードのGit HEAD
- 開始・終了時刻
- 実行段階
- 診断statusとreason_code
- 終了コード
- Cleanup status
- TUN・DROP・HTTPS・GeoIPの到達状況

保存禁止：

- APIキー
- OpenVPN設定本文
- 認証情報
- OpenVPN生ログ
- 秘密鍵・トークン

OpenVPN実行前に試行予約を永続化する。排他ロックと原子的なファイル作成を使用し、同じ固定候補の二重実行を防ぐ。

異常終了後に予約済みの試行が未確定であれば `RESULT_UNKNOWN` として扱う。再起動時に自動再試行しない。

履歴レコードが存在しても、過去の不明な実行状態を推測によってPASSやFAILに書き換えない。

Journalの書込み失敗時はOpenVPN起動を禁止する。起動後の記録失敗は安全な終了・Cleanupを優先し、正常完了と報告しない。

## 7. Result Contract

既存の `PASS` / `NOT_VERIFIED` / `BLOCKED` / `FAIL` を維持する。

`RESULT_UNKNOWN` は試行回収状態として扱い、既存の `ProbeStatus` に無条件で追加しない。

出力は秘匿情報を除去した構造化JSONとする。

- Probe結果と実行結果の回収状態を区別する
- Cleanup失敗は既存どおりFAILを優先する
- 終了コード未取得は `null` とし、成功扱いしない
- TUN未確立・DROP未検証をPASSと表現しない
- Journal記録とCLI出力は同じattempt_idで照合可能にする

出力不能の場合も、残存する予約レコードから「結果不明」を確認可能とする。

## 8. Scope Boundaries

### 変更を許容する範囲（別途実装承認後のみ）

- `vpn_orbit/live_runner.py`
- `vpn_orbit/openvpn_probe.py`
- `vpn_orbit/isolation.py`
- `vpn_orbit/runner_types.py`（必要な契約変更のみ）
- 固定候補CLI・Journal用の小さな新規モジュール
- 対応するオフラインテスト
- 実機検証用Runbook

変更ファイルは実装判断で最小化する。

### 変更しない範囲

- VPN Gate CSVのPhase 1処理
- 既存の通常候補探索CLI契約
- Supervisorの資格情報隔離モデル
- 既存のCleanup優先順位
- iOS / sing-box連携
- GitHub Actionsの自動実通信設定

OpenVPNの認証拒否原因の拡張診断は、今回の実証準備を妨げない限り対象外とする。

## 9. Offline Acceptance

実装はSuperpowers TDDで行う。

必須テスト：

- 固定ID一致・不一致・候補消失・プロファイル変更
- 最大1候補・再試行なし
- 不正CLI入力・資格情報欠落
- DROPカウンター増加時のみ証拠成立
- curl拒否のみでDROP証拠がなければFAIL
- nftables異常時のFail-Closed
- Journal予約・重複実行拒否・中断後RESULT_UNKNOWN
- JSONの秘匿情報非露出
- Cleanup失敗のFAIL優先
- 既存テストの回帰PASS

MockによるテストPASSを、実LinuxカーネルでのDROPカウンター成立や東京出口IPv4の実証と混同しない。

## 10. Pre-Live Completion Gate

次のすべてが揃えば、今回の実装Taskは完成とする。

1. 設計承認後、承認範囲内の実装が完成
2. オフラインテスト・既存回帰テストPASS
3. 変更された安全境界について失敗系テストPASS
4. 実通信なしで固定候補・Journal・Cleanup契約の整合性を検証
5. RunbookにPreflight、実行、停止、結果回収、Cleanup確認を記載
6. 実装Commit・対象スコープ・残余リスクを明示
7. Human Owner Checkpointで停止

この段階での状態は `READY_FOR_LIVE_APPROVAL` とする。

これは実通信のPASS、東京出口IPv4確認、または運用開始承認を意味しない。

## 11. Stop Conditions

以下の状態で後続実行を禁止する。

- 実行対象HEAD・環境が一致しない
- NamespaceやOpenVPN等に不明な残存がある
- 固定候補の同一性が確認できない
- 秘密情報の取扱いが不明
- Journalを安全に作成できない
- 以前の試行結果が未回収
- DROP証拠が不足
- Cleanupに異常がある

問題が生じても、追加の独立レビューや再実通信を自動開始しない。

## 12. Authority

本設計の作成・採択と、実装・GitHub書込み・実通信は別の承認とする。

- Design Adoption: **APPROVED**
- Implementation Plan Adoption: **PENDING**
- Implementation Authorization: **HOLD**
- Source Code Modification: **HOLD**
- Live Execution (KVM / GitHub Actions): **HOLD**
- Documentation-only feature branch, commit, push and PR: **AUTHORIZED for these two documents only**

後続Taskを自動で開始しない。
