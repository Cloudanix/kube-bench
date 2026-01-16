#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./build.sh [OPTIONS]
This script generates Docker images for the misconfig-cron service with multi-architecture support.

Options:
  --tag TAG              Image tag (default: latest git tag, or "latest")
  --push                 Push images to registry (default: false)
  --latest               Also tag/push "latest" (default: false)
  -h, --help             Show this help message

Examples:
  ./build.sh --tag v1.2.3
  ./build.sh --tag v1.2.3 --push
  ./build.sh --tag v1.2.3 --latest --push
'
    exit
fi

main() {
	# Default values
	CURRENT_TAG="$(git describe --tags "$(git rev-list --tags --max-count=1)" 2>/dev/null || echo "latest")"
	IMAGE_TAG="$CURRENT_TAG"
	PLATFORMS="linux/amd64,linux/arm64"
	PUSH_IMAGES="false"
	PUSH_LATEST="false"

	REGISTRY="cloudanix"

	IMAGE_NAME="misconfig-cron"
	
	# Parse command line arguments
	while [[ $# -gt 0 ]]; do
		case $1 in
			--latest)
				PUSH_LATEST="true"
				shift
				;;
			--tag)
				IMAGE_TAG="$2"
				shift 2
				;;
			--push)
				PUSH_IMAGES="true"
				shift
				;;
			*)
				echo "Unknown option: $1"
				echo "Use --help for usage information"
				exit 1
				;;
		esac
	done

	export IMAGE_TAG
	FULL_IMAGE_NAME="$REGISTRY/$IMAGE_NAME"
	
	echo "Configuration:"
	echo "  Image: $FULL_IMAGE_NAME:$IMAGE_TAG"
	echo "  Platforms: $PLATFORMS"
	echo "  Push to latest: $PUSH_LATEST"
	echo "  Push images: $PUSH_IMAGES"
	echo ""

	# Login to Docker registry if credentials are available
	if [[ "$PUSH_IMAGES" == "true" && -n "${CDX_DOCKER_PASSWORD:-}" && -n "${CDX_DOCKER_USERNAME:-}" ]]; then
		echo "Logging into Docker registry..."
		echo "$CDX_DOCKER_PASSWORD" | docker login -u "$CDX_DOCKER_USERNAME" --password-stdin
	elif [[ "$PUSH_IMAGES" == "true" ]]; then
		echo "Warning: Docker credentials not found. Assuming already logged in or using local registry."
	fi

	BUILD_TAGS=(-t "$FULL_IMAGE_NAME:$IMAGE_TAG")
	if [[ "$PUSH_LATEST" == "true" ]]; then
		BUILD_TAGS+=(-t "$FULL_IMAGE_NAME:latest")
	fi

	# Build and optionally push the main tag
	echo "Building $FULL_IMAGE_NAME:$IMAGE_TAG..."

	BUILD_CMD=(docker buildx build --platform "$PLATFORMS" --progress=plain)
	if [[ "$PUSH_IMAGES" == "true" ]]; then
		BUILD_CMD+=(--push)
	fi

	"${BUILD_CMD[@]}" "${BUILD_TAGS[@]}" \
		--build-arg "SVC_VERSION=$IMAGE_TAG" \
		--build-arg "KUBECTL_VERSION=1.35.0" \
		--progress=plain \
		. 2>&1 | tee build.log

	echo "Build completed successfully!"
	echo "Built image: $FULL_IMAGE_NAME:$IMAGE_TAG"
	if [[ "$PUSH_LATEST" == "true" ]]; then
		echo "Built image: $FULL_IMAGE_NAME:latest"
	fi
}

main "$@"
