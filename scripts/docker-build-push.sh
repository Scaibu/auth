#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

REGISTRY="${DOCKER_REGISTRY:-chiefj}"
IMAGE_NAME="${IMAGE_NAME:-llm-obs-auth}"
TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD 2>/dev/null || echo 'latest')}"
PUSH="${PUSH:-false}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build and deploy Docker image for auth service.

Options:
  -r, --registry REGISTRY   Container registry/namespace (default: \$DOCKER_REGISTRY or 'chiefj')
  -t, --tag TAG             Image tag (default: git short commit SHA or 'latest')
  -p, --push                Push image to registry after successful build
  --latest                  Also tag and push as :latest
  -h, --help                Show this message
EOF
  exit 1
}

ALSO_LATEST=false

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -r|--registry)
      REGISTRY="$2"
      shift 2
      ;;
    -t|--tag)
      TAG="$2"
      shift 2
      ;;
    -p|--push)
      PUSH=true
      shift
      ;;
    --latest)
      ALSO_LATEST=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      ;;
  esac
done

TARGET_IMAGE="${REGISTRY}/${IMAGE_NAME}:${TAG}"
LATEST_IMAGE="${REGISTRY}/${IMAGE_NAME}:latest"

echo "=========================================="
echo " Building Auth Container Image"
echo " Target: $TARGET_IMAGE"
echo " Context: $ROOT_DIR"
echo " Dockerfile: $ROOT_DIR/auth/Dockerfile"
echo "=========================================="

docker build \
  -t "$TARGET_IMAGE" \
  -f "$ROOT_DIR/auth/Dockerfile" \
  "$ROOT_DIR"

if [ "$ALSO_LATEST" = true ] && [ "$TAG" != "latest" ]; then
  docker tag "$TARGET_IMAGE" "$LATEST_IMAGE"
  echo "Tagged as: $LATEST_IMAGE"
fi

echo "Image build successful: $TARGET_IMAGE"

if [ "$PUSH" = true ]; then
  echo "=========================================="
  echo " Pushing Image to Registry"
  echo "=========================================="
  docker push "$TARGET_IMAGE"
  if [ "$ALSO_LATEST" = true ] && [ "$TAG" != "latest" ]; then
    docker push "$LATEST_IMAGE"
  fi
  echo "Image pushed successfully!"
else
  echo "Skipping push. Use -p or --push to push to registry."
fi
