package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 固定的规范小写 UUIDv7（version 字段为 7）与对照用 UUIDv4。
const (
	validUUIDv7       = "01927a3b-4c5d-7e8f-9a0b-1c2d3e4f5061"
	validUUIDv4       = "9a0b1c2d-3e4f-4a5b-8c6d-7e8f90a1b2c3"
	trustHeaderForTst = "X-Internal-Trust-Token"
	trustTokenForTst  = "s3cr3t-bridge-token"
	clientIDHeader    = "X-Client-Request-ID"
)

func newTrustedRouter(cfg config.GatewayTrustedClientRequestIDConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(ClientRequestIDWithTrustedSeed(cfg))
	router.GET("/", func(c *gin.Context) {
		value, _ := c.Request.Context().Value(ctxkey.ClientRequestID).(string)
		c.String(http.StatusOK, value)
	})
	return router
}

func enabledCfg() config.GatewayTrustedClientRequestIDConfig {
	return config.GatewayTrustedClientRequestIDConfig{
		Enabled:     true,
		TrustToken:  trustTokenForTst,
		TrustHeader: trustHeaderForTst,
	}
}

func TestTrustedSeed_SeedsWhenTrustedAndValidV7(t *testing.T) {
	router := newTrustedRouter(enabledCfg())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(trustHeaderForTst, trustTokenForTst)
	req.Header.Set(clientIDHeader, validUUIDv7)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, validUUIDv7, w.Body.String(), "受信任且合法 UUIDv7 应被播种为关联键")
	require.Equal(t, validUUIDv7, w.Header().Get(clientRequestIDHeader), "原生中间件应回显播种值")
}

func TestTrustedSeed_IgnoresWhenTokenMismatch(t *testing.T) {
	router := newTrustedRouter(enabledCfg())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(trustHeaderForTst, "wrong-token")
	req.Header.Set(clientIDHeader, validUUIDv7)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotEmpty(t, w.Body.String())
	require.NotEqual(t, validUUIDv7, w.Body.String(), "trust token 不匹配时不得采用入站 ID，应自生成")
}

func TestTrustedSeed_IgnoresWhenNoToken(t *testing.T) {
	router := newTrustedRouter(enabledCfg())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(clientIDHeader, validUUIDv7)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotEqual(t, validUUIDv7, w.Body.String(), "缺少 trust token 时不得采用入站 ID")
}

func TestTrustedSeed_IgnoresWhenDisabled(t *testing.T) {
	cfg := enabledCfg()
	cfg.Enabled = false
	router := newTrustedRouter(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(trustHeaderForTst, trustTokenForTst)
	req.Header.Set(clientIDHeader, validUUIDv7)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotEqual(t, validUUIDv7, w.Body.String(), "未启用时行为同原生，应自生成")
}

func TestTrustedSeed_IgnoresWhenEmptyConfiguredToken(t *testing.T) {
	cfg := config.GatewayTrustedClientRequestIDConfig{Enabled: true, TrustToken: "", TrustHeader: trustHeaderForTst}
	router := newTrustedRouter(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// 攻击者可能也发一个空 token 头试图匹配空配置；必须被拒绝。
	req.Header.Set(trustHeaderForTst, "")
	req.Header.Set(clientIDHeader, validUUIDv7)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotEqual(t, validUUIDv7, w.Body.String(), "配置 token 为空时禁止播种（安全默认）")
}

func TestTrustedSeed_RejectsNonV7AndNonCanonical(t *testing.T) {
	cases := map[string]string{
		"uuidv4":        validUUIDv4,
		"uppercase_v7":  "01927A3B-4C5D-7E8F-9A0B-1C2D3E4F5061",
		"no_dashes":     "01927a3b4c5d7e8f9a0b1c2d3e4f5061",
		"braces":        "{01927a3b-4c5d-7e8f-9a0b-1c2d3e4f5061}",
		"garbage":       "not-a-uuid",
		"empty":         "",
		"trailing_junk": validUUIDv7 + "x",
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			router := newTrustedRouter(enabledCfg())
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(trustHeaderForTst, trustTokenForTst)
			if id != "" {
				req.Header.Set(clientIDHeader, id)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			require.NotEqual(t, id, w.Body.String(), "非规范/非 UUIDv7 输入不得被播种")
			require.NotEmpty(t, w.Body.String(), "应回退到自生成 ID")
		})
	}
}

func TestTrustedSeed_DefaultTrustHeaderWhenUnset(t *testing.T) {
	cfg := config.GatewayTrustedClientRequestIDConfig{Enabled: true, TrustToken: trustTokenForTst, TrustHeader: ""}
	router := newTrustedRouter(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(defaultTrustedClientRequestIDHeader, trustTokenForTst)
	req.Header.Set(clientIDHeader, validUUIDv7)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, validUUIDv7, w.Body.String(), "TrustHeader 未配置时应回退到默认头名")
}

func TestCanonicalUUIDv7(t *testing.T) {
	if _, ok := canonicalUUIDv7(validUUIDv7); !ok {
		t.Fatalf("expected %s to be accepted as canonical UUIDv7", validUUIDv7)
	}
	if _, ok := canonicalUUIDv7(validUUIDv4); ok {
		t.Fatalf("expected UUIDv4 to be rejected")
	}
}
