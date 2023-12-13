package url

import (
	"strings"
)

// PathSplitQuery splits a path from a query.
// 通过 "?" 字符串切分 path 和 query 部分
func PathSplitQuery(pathAndQuery string) (string, string) {
	// 查找 "?" 的下标
	i := strings.Index(pathAndQuery, "?")
	if i >= 0 {
		// 返回 path、query 部分
		return pathAndQuery[:i], pathAndQuery[i+1:]
	}

	// 不存在参数部分
	return pathAndQuery, ""
}
