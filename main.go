package main

import (
	"github.com/xiehqing/hitoken/core"
	"github.com/xiehqing/hitoken/htputil"
	"github.com/xiehqing/hitoken/storage/memory"
)

func init() {
	htputil.SetManager(
		core.NewBuilder().
			Storage(memory.NewStorage()).TokenName("Authorization").
			Timeout(86400).                 // 24小时
			TokenStyle(core.TokenStyleJWT). // Token风格
			JwtSecretKey("www.zorktech.com").
			IsPrintBanner(true). // 显示启动Banner
			Build(),
	)
}

func main() {
	token, _ := htputil.Login(1000)
	println("登录成功，Token:", token)
	login := htputil.IsLogin(token)
	println("是否登录：", login)
}
