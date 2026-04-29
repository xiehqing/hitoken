package hertz

import (
	"context"
	"errors"
	"net/http"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/utils"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/xiehqing/hitoken/core"
)

// Plugin Hertz plugin for Hi-Token | Hertz插件
type Plugin struct {
	manager *core.Manager
}

// NewPlugin creates a Hertz plugin | 创建Hertz插件
func NewPlugin(manager *core.Manager) *Plugin {
	return &Plugin{
		manager: manager,
	}
}

// AuthMiddleware authentication middleware | 认证中间件
func (p *Plugin) AuthMiddleware() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		hCtx := NewHertzContext(c)
		saCtx := core.NewContext(hCtx, p.manager)

		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(c, err)
			c.Abort()
			return
		}

		// Store Hi-Token context in Hertz context | 将Hi-Token上下文存储到Hertz上下文
		c.Set("hitoken", saCtx)
		c.Next(ctx)
	}
}

// PathAuthMiddleware path-based authentication middleware | 基于路径的鉴权中间件
func (p *Plugin) PathAuthMiddleware(config *core.PathAuthConfig) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		path := string(c.Path())
		token := string(c.GetHeader(p.manager.GetConfig().TokenName))
		if token == "" {
			token = string(c.Cookie(p.manager.GetConfig().TokenName))
		}

		result := core.ProcessAuth(path, token, config, p.manager)

		if result.ShouldReject() {
			writeErrorResponse(c, core.NewPathAuthRequiredError(path))
			c.Abort()
			return
		}

		if result.IsValid && result.TokenInfo != nil {
			hCtx := NewHertzContext(c)
			saCtx := core.NewContext(hCtx, p.manager)
			c.Set("hitoken", saCtx)
			c.Set("loginID", result.LoginID())
		}

		c.Next(ctx)
	}
}

// PermissionRequired permission validation middleware | 权限验证中间件
func (p *Plugin) PermissionRequired(permission string) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		hCtx := NewHertzContext(c)
		saCtx := core.NewContext(hCtx, p.manager)

		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(c, err)
			c.Abort()
			return
		}

		// Check permission | 检查权限
		if !saCtx.HasPermission(permission) {
			writeErrorResponse(c, core.NewPermissionDeniedError(permission))
			c.Abort()
			return
		}

		c.Set("hitoken", saCtx)
		c.Next(ctx)
	}
}

// RoleRequired role validation middleware | 角色验证中间件
func (p *Plugin) RoleRequired(role string) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		hCtx := NewHertzContext(c)
		saCtx := core.NewContext(hCtx, p.manager)

		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(c, err)
			c.Abort()
			return
		}

		// Check role | 检查角色
		if !saCtx.HasRole(role) {
			writeErrorResponse(c, core.NewRoleDeniedError(role))
			c.Abort()
			return
		}

		c.Set("hitoken", saCtx)
		c.Next(ctx)
	}
}

// LoginHandler login handler example | 登录处理器示例
func (p *Plugin) LoginHandler(c *app.RequestContext) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Device   string `json:"device"`
	}

	if err := c.BindJSON(&req); err != nil {
		writeErrorResponse(c, core.NewError(core.CodeBadRequest, "invalid request parameters", err))
		return
	}

	// Login | 登录
	device := req.Device
	if device == "" {
		device = "default"
	}

	token, err := p.manager.Login(req.Username, device)
	if err != nil {
		writeErrorResponse(c, core.NewError(core.CodeServerError, "login failed", err))
		return
	}

	// Set cookie (optional) | 设置Cookie（可选）
	cfg := p.manager.GetConfig()
	if cfg.IsReadCookie {
		maxAge := int(cfg.Timeout)
		if maxAge < 0 {
			maxAge = 0
		}
		var sameSite protocol.CookieSameSite
		switch cfg.CookieConfig.SameSite {
		case "Strict":
			sameSite = protocol.CookieSameSiteStrictMode
		case "Lax":
			sameSite = protocol.CookieSameSiteLaxMode
		case "None":
			sameSite = protocol.CookieSameSiteNoneMode
		}
		c.SetCookie(
			cfg.TokenName,
			token,
			maxAge,
			cfg.CookieConfig.Path,
			cfg.CookieConfig.Domain,
			sameSite,
			cfg.CookieConfig.Secure,
			cfg.CookieConfig.HttpOnly,
		)
	}

	writeSuccessResponse(c, utils.H{
		"token": token,
	})
}

// LogoutHandler logout handler | 登出处理器
func (p *Plugin) LogoutHandler(c *app.RequestContext) {
	hCtx := NewHertzContext(c)
	saCtx := core.NewContext(hCtx, p.manager)

	loginID, err := saCtx.GetLoginID()
	if err != nil {
		writeErrorResponse(c, err)
		return
	}

	if err := p.manager.Logout(loginID); err != nil {
		writeErrorResponse(c, core.NewError(core.CodeServerError, "logout failed", err))
		return
	}

	writeSuccessResponse(c, utils.H{
		"message": "logout successful",
	})
}

// UserInfoHandler user info handler example | 获取用户信息处理器示例
func (p *Plugin) UserInfoHandler(c *app.RequestContext) {
	hCtx := NewHertzContext(c)
	saCtx := core.NewContext(hCtx, p.manager)

	loginID, err := saCtx.GetLoginID()
	if err != nil {
		writeErrorResponse(c, err)
		return
	}

	// Get user permissions and roles | 获取用户权限和角色
	permissions, _ := p.manager.GetPermissions(loginID)
	roles, _ := p.manager.GetRoles(loginID)

	writeSuccessResponse(c, utils.H{
		"loginId":     loginID,
		"permissions": permissions,
		"roles":       roles,
	})
}

// GetHiToken gets Hi-Token context from Hertz context | 从Hertz上下文获取Hi-Token上下文
func GetHiToken(c *app.RequestContext) (*core.HiTokenContext, bool) {
	hitoken, exists := c.Get("hitoken")
	if !exists {
		return nil, false
	}
	ctx, ok := hitoken.(*core.HiTokenContext)
	return ctx, ok
}

// ============ Error Handling Helpers | 错误处理辅助函数 ============

// writeErrorResponse writes a standardized error response | 写入标准化的错误响应
func writeErrorResponse(c *app.RequestContext, err error) {
	var saErr *core.HiTokenError
	var code int
	var message string
	var httpStatus int

	// Check if it's a HiTokenError | 检查是否为HiTokenError
	if errors.As(err, &saErr) {
		code = saErr.Code
		message = saErr.Message
		httpStatus = getHTTPStatusFromCode(code)
	} else {
		// Handle standard errors | 处理标准错误
		code = core.CodeServerError
		message = err.Error()
		httpStatus = http.StatusInternalServerError
	}

	c.JSON(httpStatus, utils.H{
		"code":    code,
		"message": message,
		"error":   err.Error(),
	})
}

// writeSuccessResponse writes a standardized success response | 写入标准化的成功响应
func writeSuccessResponse(c *app.RequestContext, data interface{}) {
	c.JSON(http.StatusOK, utils.H{
		"code":    core.CodeSuccess,
		"message": "success",
		"data":    data,
	})
}

// getHTTPStatusFromCode converts Hi-Token error code to HTTP status | 将Hi-Token错误码转换为HTTP状态码
func getHTTPStatusFromCode(code int) int {
	switch code {
	case core.CodeNotLogin:
		return http.StatusUnauthorized
	case core.CodePermissionDenied:
		return http.StatusForbidden
	case core.CodeBadRequest:
		return http.StatusBadRequest
	case core.CodeNotFound:
		return http.StatusNotFound
	case core.CodeServerError:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}
