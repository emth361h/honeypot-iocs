#!/usr/bin/env bash
# publish.sh - VM側の唯一の仕事: 最新コード取得 → 生ログから集約観測を生成 → push。
# 分類・feed生成・ASN/TI enrichment・CHANGELOG・検証はすべて GitHub Actions 側で完結する。
#
# 環境依存の値 (実ログパス・自IP・除外network・decoy設定) は
# /etc/honeypot-iocs/export.env から読む。repoには実値を置かない (.env.example参照)。
#
# 自己更新: 実行のたびに origin/master へ追従するため、VM側のスクリプト保守は不要。
set -euo pipefail
cd "$(dirname "$0")/.."

DEPLOY_KEY="${HONEYPOT_DEPLOY_KEY:-/etc/honeypot-iocs/deploy_key}"
export GIT_SSH_COMMAND="ssh -i '$DEPLOY_KEY' -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes"

# 環境設定 (private。repo外)
ENV_FILE="${HONEYPOT_EXPORT_ENV:-/etc/honeypot-iocs/export.env}"
if [ -f "$ENV_FILE" ]; then
    set -a; . "$ENV_FILE"; set +a
fi

# 1) 自己更新 (ローカル修正は持たせないため reset で良い。観測生成はこの後)
BEFORE="$(git rev-parse HEAD 2>/dev/null || echo none)"
git fetch -q origin master
git reset -q --hard origin/master
AFTER="$(git rev-parse HEAD)"
if [ "$BEFORE" != "$AFTER" ] && [ "${PUBLISH_REEXEC:-}" != "1" ]; then
    PUBLISH_REEXEC=1 exec bash scripts/publish.sh "$@"
fi

# 2) 集約観測の生成 (昨日+今日。秒精度timestamp/session ID/コマンド本文は出力構造に存在しない)
D="$(date -u +%F)"
Y="$(date -u -d yesterday +%F)"
python3 scripts/honeypot_export.py --out observations --date "$Y"
python3 scripts/honeypot_export.py --out observations --date "$D"

# 3) push前の最小検査 (公開不能なデータの混入だけ落とす。詳細検証はActions)
python3 scripts/validate_raw.py observations

# 4) 差分があれば collector として commit+push
git add observations/
if git diff --cached --quiet; then
    echo "no new observations - nothing to publish"
    exit 0
fi
git -c user.name="honeypot-collector" -c user.email="collector@honeypot.local" \
    commit -q -m "collector: add observations for $D"
git push -q origin master
echo "published: collector: add observations for $D"
