#!/bin/bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT
sed '/^main "\$@"$/d' "$ROOT_DIR/deploy/install.sh" > "$TEMP_DIR/install-lib.sh"

cat > "$TEMP_DIR/curl" <<'EOF'
#!/bin/bash
url="${!#}"
case "$url" in
    *"/releases?per_page=100")
        cat <<'JSON'
[
  {"tag_name": "v0.1.178"},
  {"tag_name": "v0.1.178-rc.1"},
  {"tag_name": "v0.1.177-madao.2"},
  {"tag_name": "v0.1.178-madao.1"},
  {"tag_name": "v0.1.177-madao.1"},
  {"tag_name": "v0.1.178-madao.0"},
  {"tag_name": "v00.1.178-madao.3"}
]
JSON
        ;;
    *"/releases/tags/v0.1.178-madao.1")
        printf '{"assets":[{"name":"docker-only"}]}\n'
        ;;
    *"/releases/tags/v0.1.177-madao.2")
        printf '{"assets":[{"name":"sub2api_0.1.177-madao.2_linux_amd64.tar.gz"}]}\n'
        ;;
    *)
        printf '{}\n'
        ;;
esac
EOF
chmod +x "$TEMP_DIR/curl"

PATH="$TEMP_DIR:$PATH" "$BASH" -c '
    source "$1"
    LANG_CHOICE="en"
    OS="linux"
    ARCH="amd64"

    versions=$(get_channel_versions)
    expected=$'"'"'v0.1.178-madao.1\nv0.1.177-madao.2\nv0.1.177-madao.1'"'"'
    if [ "$versions" != "$expected" ]; then
        printf "unexpected channel versions:\n%s\n" "$versions" >&2
        exit 1
    fi

    get_latest_version >/dev/null
    if [ "$LATEST_VERSION" != "v0.1.177-madao.2" ]; then
        echo "unexpected latest installable version: $LATEST_VERSION" >&2
        exit 1
    fi

    validated=$(validate_version v0.1.177-madao.2 2>/dev/null)
    if [ "$validated" != "v0.1.177-madao.2" ]; then
        echo "unexpected validated version: $validated" >&2
        exit 1
    fi
    if (validate_version v0.1.178-rc.1 >/dev/null 2>&1); then
        echo "installer accepted a release from another channel" >&2
        exit 1
    fi
    if (validate_version v00.1.178-madao.3 >/dev/null 2>&1); then
        echo "installer accepted a non-SemVer release" >&2
        exit 1
    fi
' bash "$TEMP_DIR/install-lib.sh"

echo "install release channel checks passed"
