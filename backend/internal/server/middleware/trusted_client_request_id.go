package middleware

import (
	"context"
	"crypto/subtle"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// defaultTrustedClientRequestIDHeader 是携带受信任 trust token 的默认请求头名。
const defaultTrustedClientRequestIDHeader = "X-Internal-Trust-Token"

// ClientRequestIDWithTrustedSeed 组合「受信任入站播种」与原生 ClientRequestID。
//
// 当 cfg.Enabled 且请求在 trust header 中携带匹配的 trust token 时，从入站
// X-Client-Request-ID 播种 ctxkey.ClientRequestID（仅接受规范小写 UUIDv7）；
// 随后交由原生 ClientRequestID() 沿用该值并回显响应头，使 usage_logs.request_id
// 恒为 client:<平台请求ID>。未启用、未受信任或非法 UUID 时，行为与原生完全
// 一致（自生成 UUID）。
//
// 播种在原生逻辑之前完成，因此不改动 ClientRequestID() 本身，也不改变任何路由
// 注册点——仅替换 clientRequestID 中间件的构造。平台契约见
// transfers/contracts/request-id.md。
func ClientRequestIDWithTrustedSeed(cfg config.GatewayTrustedClientRequestIDConfig) gin.HandlerFunc {
	native := ClientRequestID()
	seed := trustedClientRequestIDSeeder(cfg)
	return func(c *gin.Context) {
		seed(c)
		native(c)
	}
}

// trustedClientRequestIDSeeder 返回一个仅在受信任且合法时向请求 context 播种
// ClientRequestID 的函数；它不调用 c.Next()，只负责改写 c.Request 的 context。
func trustedClientRequestIDSeeder(cfg config.GatewayTrustedClientRequestIDConfig) func(*gin.Context) {
	trustToken := cfg.TrustToken
	enabled := cfg.Enabled && strings.TrimSpace(trustToken) != ""
	trustHeader := strings.TrimSpace(cfg.TrustHeader)
	if trustHeader == "" {
		trustHeader = defaultTrustedClientRequestIDHeader
	}
	tokenBytes := []byte(trustToken)

	return func(c *gin.Context) {
		if !enabled || c.Request == nil {
			return
		}
		// 常量时间比较，避免通过响应时间侧信道爆破 trust token。
		presented := []byte(c.GetHeader(trustHeader))
		if subtle.ConstantTimeCompare(presented, tokenBytes) != 1 {
			return
		}
		id, ok := canonicalUUIDv7(strings.TrimSpace(c.GetHeader(clientRequestIDHeader)))
		if !ok {
			return
		}
		ctx := context.WithValue(c.Request.Context(), ctxkey.ClientRequestID, id)
		c.Request = c.Request.WithContext(ctx)
	}
}

// canonicalUUIDv7 仅接受规范小写、版本号为 7 的 UUID。
//
// uuid.Parse 会宽松接受大写、花括号、urn 前缀、无连字符等多种形态；这里额外要求
// 输入与规范字符串（36 字符、连字符、小写十六进制）严格相等，并要求版本为 7，
// 从而拒绝非规范形态与非 UUIDv7 的入站值。
func canonicalUUIDv7(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return "", false
	}
	if id.Version() != 7 {
		return "", false
	}
	if canonical := id.String(); canonical == raw {
		return canonical, true
	}
	return "", false
}
