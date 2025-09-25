#!/usr/bin/zsh
set -euo pipefail

# This script builds the OpenAPI documents, rendering them into YAML and JSON.
#
# The main inputs for this are the "openapi.jq" files in the "v?" directories.
# These are jq(1) scripts that are executed with no input in the relevant
# directory; they're expected to output a valid OpenAPI document. All the JSON
# Schema documents in the matching "httptransport/types/v?" directory are
# copied into the working directory. Matching files in the "examples"
# subdirectory will be slipstreamed to the expected field.
#
# The result is then "bundled" into one document, then linted, rendered out to
# both YAML and JSON, and strings to be used as HTTP Etags are written out.

for cmd in sha256sum git jq yq npx; do
	if ! command -v "$cmd" &>/dev/null; then
		print missing needed command: "$cmd" >&2
		exit 1
	fi
done

function jq() {
	command jq --exit-status --compact-output "$@"
}

function yq() {
	command yq --exit-status "$@"
}

function schemalint() {
	npx --yes @sourcemeta/jsonschema metaschema --resolve "$1" "$1"
	npx --yes @sourcemeta/jsonschema lint       --resolve "$1" "$1"
}

function render() {
	function TRAPEXIT() {
		rm openapi.*.{json,yaml}(N) *.schema.json(N)
		popd -q
	}
	pushd -q "${1?missing directory argument}"
	local v=${1:A:t}
	local t=${1:A:h:h}/types/v1

	schemalint "$t"
	for f in ${t}/*.schema.json; do
		local ex=examples/${${f:t}%.schema.json}.json
		if [[ -f "$ex" ]]; then
			jq --slurpfile ex "${ex}" 'setpath(["examples"]; $ex)' "$f" > "${f:t}"
		else
			cp "$f" .
		fi
	done

	jq --null-input \
		'reduce (inputs|(.["$id"]|split("/")|.[-1]|rtrimstr(".schema.json")) as $k|{components:{schemas:{$k:.}}}) as $it({};. * $it)'\
		*.schema.json >openapi.types.json


	jq --null-input -L "${1:A:h}/lib" --from-file openapi.jq >openapi.frag.json
	jq --null-input 'reduce inputs as $it({};. * $it)' openapi.{frag,types}.json >openapi.json

	yq -pj eval . <openapi.json >openapi.yaml
	# Need some validator that actually works >:(

	sha256sum openapi.{json,yaml} |
		awk '{printf "\"%s\"", $1 >$2".etag" }'
}

local root=$(git rev-parse --show-toplevel)
for d in ${root}/httptransport/api/v*/; do
	render "$d"
done
