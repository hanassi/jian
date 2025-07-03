#!/bin/bash

DOMAIN_NAME=$1

if [ -z "$DOMAIN_NAME" ]; then
  echo "Usage: $0 <OpenSearchDomainName>"
  exit 1
fi

echo "🔍 점검 대상 도메인: $DOMAIN_NAME"
echo "-------------------------------"

# 기본 정보
aws opensearch describe-domain --domain-name "$DOMAIN_NAME" --query "DomainStatus.{Endpoint:Endpoint, EngineVersion:EngineVersion, VPC:VPCOptions}" --output table

# 퍼블릭 여부
endpoint=$(aws opensearch describe-domain --domain-name "$DOMAIN_NAME" --query "DomainStatus.Endpoint" --output text)
if [[ "$endpoint" == vpc-* ]]; then
  echo "✅ VPC 전용 도메인입니다."
else
  echo "❌ 퍼블릭 도메인입니다. 보안에 취약할 수 있습니다."
fi

# HTTPS 강제 사용
echo -n "🔐 HTTPS 강제 여부: "
aws opensearch describe-domain --domain-name "$DOMAIN_NAME" \
  --query "DomainStatus.DomainEndpointOptions.EnforceHTTPS"

# 저장 암호화
echo -n "🔐 저장 암호화 (at-rest): "
aws opensearch describe-domain --domain-name "$DOMAIN_NAME" \
  --query "DomainStatus.EncryptionAtRestOptions.Enabled"

# 노드 간 암호화
echo -n "🔐 노드 간 암호화: "
aws opensearch describe-domain --domain-name "$DOMAIN_NAME" \
  --query "DomainStatus.NodeToNodeEncryptionOptions.Enabled"

# 감사 로그 설정
echo "📝 로그 설정:"
aws opensearch describe-domain --domain-name "$DOMAIN_NAME" \
  --query "DomainStatus.LogPublishingOptions" | jq

# IAM 정책
echo "🔐 IAM Access Policy:"
aws opensearch describe-domain --domain-name "$DOMAIN_NAME" \
  --query "DomainStatus.AccessPolicies" --output text
