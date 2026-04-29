package htputil

import (
	"fmt"
	"github.com/xiehqing/hitoken/core/manager"
	"github.com/xiehqing/hitoken/core/oauth2"
	"github.com/xiehqing/hitoken/core/security"
	"github.com/xiehqing/hitoken/core/session"
	"sync"
	"time"
)

var (
	TokenValueKey  = "stplogic:tokenvalue"
	LoginIdKey     = "stplogic:loginid"
	PermissionsKey = "stplogic:permissions"
	RolesKey       = "stplogic:roles"
)

type HtpLogic struct {
	manager *manager.Manager
	mu      sync.RWMutex
}

func NewHtpLogic(mrg *manager.Manager) *HtpLogic {
	return &HtpLogic{manager: mrg}
}

// GetManager gets the global Manager | 获取全局Manager
func (s *HtpLogic) GetManager() *manager.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.manager == nil {
		panic("HtpLogic not initialized.")
	}
	return s.manager
}

func (s *HtpLogic) SetManager(manager *manager.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manager = manager
}

// ============ Authentication | 登录认证 ============

// Login performs user login | 用户登录
func (s *HtpLogic) Login(loginID interface{}, device ...string) (string, error) {
	return s.manager.Login(toString(loginID), device...)
}

// LoginByToken performs login with specified token | 使用指定Token登录
func (s *HtpLogic) LoginByToken(loginID interface{}, tokenValue string, device ...string) error {
	return s.manager.LoginByToken(toString(loginID), tokenValue, device...)
}

// Logout performs user logout | 用户登出
func (s *HtpLogic) Logout(loginID interface{}, device ...string) error {
	return s.manager.Logout(toString(loginID), device...)
}

// LogoutByToken performs logout by token | 根据Token登出
func (s *HtpLogic) LogoutByToken(tokenValue string) error {
	return s.manager.LogoutByToken(tokenValue)
}

// IsLogin checks if the user is logged in | 检查用户是否已登录
func (s *HtpLogic) IsLogin(tokenValue string) bool {
	return s.manager.IsLogin(tokenValue)
}

// CheckLogin checks login status (throws error if not logged in) | 检查登录状态（未登录抛出错误）
func (s *HtpLogic) CheckLogin(tokenValue string) error {
	return s.manager.CheckLogin(tokenValue)
}

// GetLoginID gets the login ID from token | 从Token获取登录ID
func (s *HtpLogic) GetLoginID(tokenValue string) (string, error) {
	return s.manager.GetLoginID(tokenValue)
}

// GetLoginIDNotCheck gets login ID without checking | 获取登录ID（不检查）
func (s *HtpLogic) GetLoginIDNotCheck(tokenValue string) (string, error) {
	return s.manager.GetLoginIDNotCheck(tokenValue)
}

// GetTokenValue gets the token value for a login ID | 获取登录ID对应的Token值
func (s *HtpLogic) GetTokenValue(loginID interface{}, device ...string) (string, error) {
	return s.manager.GetTokenValue(toString(loginID), device...)
}

// GetTokenInfo gets token information | 获取Token信息
func (s *HtpLogic) GetTokenInfo(tokenValue string) (*manager.TokenInfo, error) {
	return s.manager.GetTokenInfo(tokenValue)
}

// ============ Kickout | 踢人下线 ============

// Kickout kicks out a user session | 踢人下线
func (s *HtpLogic) Kickout(loginID interface{}, device ...string) error {
	return s.manager.Kickout(toString(loginID), device...)
}

// ============ Account Disable | 账号封禁 ============

// Disable disables an account for specified duration | 封禁账号（指定时长）
func (s *HtpLogic) Disable(loginID interface{}, duration time.Duration) error {
	return s.manager.Disable(toString(loginID), duration)
}

// Untie re-enables a disabled account | 解封账号
func (s *HtpLogic) Untie(loginID interface{}) error {
	return s.manager.Untie(toString(loginID))
}

// IsDisable checks if an account is disabled | 检查账号是否被封禁
func (s *HtpLogic) IsDisable(loginID interface{}) bool {
	return s.manager.IsDisable(toString(loginID))
}

// GetDisableTime gets remaining disable time in seconds | 获取剩余封禁时间（秒）
func (s *HtpLogic) GetDisableTime(loginID interface{}) (int64, error) {
	return s.manager.GetDisableTime(toString(loginID))
}

// ============ Session Management | Session管理 ============

// GetSession gets session by login ID | 根据登录ID获取Session
func (s *HtpLogic) GetSession(loginID interface{}) (*session.Session, error) {
	return s.manager.GetSession(toString(loginID))
}

// GetSessionByToken gets session by token | 根据Token获取Session
func (s *HtpLogic) GetSessionByToken(tokenValue string) (*session.Session, error) {
	return s.manager.GetSessionByToken(tokenValue)
}

// DeleteSession deletes a session | 删除Session
func (s *HtpLogic) DeleteSession(loginID interface{}) error {
	return s.manager.DeleteSession(toString(loginID))
}

// ============ Permission Verification | 权限验证 ============

// SetPermissions sets permissions for a login ID | 设置用户权限
func (s *HtpLogic) SetPermissions(loginID interface{}, permissions []string) error {
	return s.manager.SetPermissions(toString(loginID), permissions)
}

// GetPermissions gets permission list | 获取权限列表
func (s *HtpLogic) GetPermissions(loginID interface{}) ([]string, error) {
	return s.manager.GetPermissions(toString(loginID))
}

// HasPermission checks if has specified permission | 检查是否拥有指定权限
func (s *HtpLogic) HasPermission(loginID interface{}, permission string) bool {
	return s.manager.HasPermission(toString(loginID), permission)
}

// HasPermissionsAnd checks if has all permissions (AND logic) | 检查是否拥有所有权限（AND逻辑）
func (s *HtpLogic) HasPermissionsAnd(loginID interface{}, permissions []string) bool {
	return s.manager.HasPermissionsAnd(toString(loginID), permissions)
}

// HasPermissionsOr checks if has any permission (OR logic) | 检查是否拥有任一权限（OR逻辑）
func (s *HtpLogic) HasPermissionsOr(loginID interface{}, permissions []string) bool {
	return s.manager.HasPermissionsOr(toString(loginID), permissions)
}

// ============ Role Management | 角色管理 ============

// SetRoles sets roles for a login ID | 设置用户角色
func (s *HtpLogic) SetRoles(loginID interface{}, roles []string) error {
	return s.manager.SetRoles(toString(loginID), roles)
}

// GetRoles gets role list | 获取角色列表
func (s *HtpLogic) GetRoles(loginID interface{}) ([]string, error) {
	return s.manager.GetRoles(toString(loginID))
}

// HasRole checks if has specified role | 检查是否拥有指定角色
func (s *HtpLogic) HasRole(loginID interface{}, role string) bool {
	return s.manager.HasRole(toString(loginID), role)
}

// HasRolesAnd checks if has all roles (AND logic) | 检查是否拥有所有角色（AND逻辑）
func (s *HtpLogic) HasRolesAnd(loginID interface{}, roles []string) bool {
	return s.manager.HasRolesAnd(toString(loginID), roles)
}

// HasRolesOr 检查是否拥有任一角色（OR）
func (s *HtpLogic) HasRolesOr(loginID interface{}, roles []string) bool {
	return s.manager.HasRolesOr(toString(loginID), roles)
}

// ============ Token标签 ============

// SetTokenTag 设置Token标签
func (s *HtpLogic) SetTokenTag(tokenValue, tag string) error {
	return s.manager.SetTokenTag(tokenValue, tag)
}

// GetTokenTag 获取Token标签
func (s *HtpLogic) GetTokenTag(tokenValue string) (string, error) {
	return s.manager.GetTokenTag(tokenValue)
}

// ============ 会话查询 ============

// GetTokenValueList 获取指定账号的所有Token
func (s *HtpLogic) GetTokenValueList(loginID interface{}) ([]string, error) {
	return s.manager.GetTokenValueListByLoginID(toString(loginID))
}

// GetSessionCount 获取指定账号的Session数量
func (s *HtpLogic) GetSessionCount(loginID interface{}) (int, error) {
	return s.manager.GetSessionCountByLoginID(toString(loginID))
}

func (s *HtpLogic) GenerateNonce() (string, error) {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	return s.manager.GenerateNonce()
}

func (s *HtpLogic) VerifyNonce(nonce string) bool {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	return s.manager.VerifyNonce(nonce)
}

func (s *HtpLogic) LoginWithRefreshToken(loginID interface{}, device ...string) (*security.RefreshTokenInfo, error) {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	deviceType := "default"
	if len(device) > 0 {
		deviceType = device[0]
	}
	return s.manager.LoginWithRefreshToken(fmt.Sprintf("%v", loginID), deviceType)
}

func (s *HtpLogic) RefreshAccessToken(refreshToken string) (*security.RefreshTokenInfo, error) {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	return s.manager.RefreshAccessToken(refreshToken)
}

func (s *HtpLogic) RevokeRefreshToken(refreshToken string) error {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	return s.manager.RevokeRefreshToken(refreshToken)
}

func (s *HtpLogic) GetOAuth2Server() *oauth2.OAuth2Server {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	return s.manager.GetOAuth2Server()
}

// ============ Check Functions for Token-based operations | 基于Token的检查函数 ============

// CheckDisable checks if the account associated with the token is disabled | 检查Token对应账号是否被封禁
func (s *HtpLogic) CheckDisable(tokenValue string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if s.IsDisable(loginID) {
		return fmt.Errorf("account is disabled")
	}
	return nil
}

// CheckPermission checks if the token has the specified permission | 检查Token是否拥有指定权限
func (s *HtpLogic) CheckPermission(tokenValue string, permission string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasPermission(loginID, permission) {
		return fmt.Errorf("permission denied: %s", permission)
	}
	return nil
}

// CheckPermissionAnd checks if the token has all specified permissions | 检查Token是否拥有所有指定权限
func (s *HtpLogic) CheckPermissionAnd(tokenValue string, permissions []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasPermissionsAnd(loginID, permissions) {
		return fmt.Errorf("permission denied: %v", permissions)
	}
	return nil
}

// CheckPermissionOr checks if the token has any of the specified permissions | 检查Token是否拥有任一指定权限
func (s *HtpLogic) CheckPermissionOr(tokenValue string, permissions []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasPermissionsOr(loginID, permissions) {
		return fmt.Errorf("permission denied: %v", permissions)
	}
	return nil
}

// GetPermissionList gets permission list for the token | 获取Token对应的权限列表
func (s *HtpLogic) GetPermissionList(tokenValue string) ([]string, error) {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return s.GetPermissions(loginID)
}

// CheckRole checks if the token has the specified role | 检查Token是否拥有指定角色
func (s *HtpLogic) CheckRole(tokenValue string, role string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasRole(loginID, role) {
		return fmt.Errorf("role denied: %s", role)
	}
	return nil
}

// CheckRoleAnd checks if the token has all specified roles | 检查Token是否拥有所有指定角色
func (s *HtpLogic) CheckRoleAnd(tokenValue string, roles []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasRolesAnd(loginID, roles) {
		return fmt.Errorf("role denied: %v", roles)
	}
	return nil
}

// CheckRoleOr checks if the token has any of the specified roles | 检查Token是否拥有任一指定角色
func (s *HtpLogic) CheckRoleOr(tokenValue string, roles []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasRolesOr(loginID, roles) {
		return fmt.Errorf("role denied: %v", roles)
	}
	return nil
}

// GetRoleList gets role list for the token | 获取Token对应的角色列表
func (s *HtpLogic) GetRoleList(tokenValue string) ([]string, error) {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return GetRoles(loginID)
}

// GetTokenSession gets session for the token | 获取Token对应的Session
func (s *HtpLogic) GetTokenSession(tokenValue string) (*session.Session, error) {
	return GetSessionByToken(tokenValue)
}

// CloseManager Closes the manager and releases all resources | 关闭管理器并释放所有资源
func (s *HtpLogic) CloseManager() {
	s.manager.CloseManager()
}
