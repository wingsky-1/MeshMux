// Package web 保持单包平铺：server_*.go 只做 HTTP 鉴权/参数校验与稳定
// 码映射，持久化必须经 store_*.go 事务；server_* 禁止直连 sql.DB。
package web
