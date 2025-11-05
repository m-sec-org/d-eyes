package utils

import (
	"errors"
	"github.com/hashicorp/go-version"
	"regexp"
	"strings"
)

// ParseVersion 解决版本问题
//
// 当存在 ~= 使用当前 ~= 的版本
//
// 当存在 > 或者 < 时候使用<后面跟的版本
//
// 当存在 >= 使用后面跟的版本
//
// 当存在 <= 使用后面跟的版本
//
// 当存在 >= 和 <= 时候使用 <=后面跟的版本
// 最多只有两个版本，目前考虑
func ParseVersion(versionString string) (string, error) {
	// 清楚空格，去除两边的空格
	versionNew := strings.TrimSpace(strings.ReplaceAll(versionString, " ", ""))
	versionSplit := strings.Split(versionNew, ",")
	if len(versionSplit) == 2 {
		//firstVersion, err := version.NewVersion(versionSplit[0])
		//secondVersion, err := version.NewVersion(versionSplit[1])
		//if err != nil {
		//	return "", err
		//}
		// 两个都有等号
		if strings.ContainsAny(versionSplit[0], "=") && strings.ContainsAny(versionSplit[1], "=") {
			// 对比版本号
			firstVersion, err := version.NewVersion(parseSemanticVersion(versionSplit[0]))
			secondVersion, err := version.NewVersion(parseSemanticVersion(versionSplit[1]))
			if err != nil {
				return "", err
			}
			if firstVersion.LessThan(secondVersion) {
				return secondVersion.String(), nil
			} else {
				return firstVersion.String(), nil
			}
		}
		if strings.ContainsAny(versionSplit[0], "=") {
			return parseSemanticVersion(versionSplit[0]), nil
		}
		if strings.ContainsAny(versionSplit[1], "=") {
			return parseSemanticVersion(versionSplit[1]), nil
		}
		if !strings.ContainsAny(versionSplit[0], "=") && !strings.ContainsAny(versionSplit[1], "=") {
			// 对比版本号
			firstVersion, err := version.NewVersion(parseSemanticVersion(versionSplit[0]))
			secondVersion, err := version.NewVersion(parseSemanticVersion(versionSplit[1]))
			if err != nil {
				return "", err
			}
			if firstVersion.LessThan(secondVersion) {
				return secondVersion.String(), nil
			} else {
				return firstVersion.String(), nil
			}
		}

	}
	if len(versionSplit) == 1 {
		semanticVersion := parseSemanticVersion(versionSplit[0])
		if semanticVersion == "" {
			return "", errors.New("version string is empty")
		}
		newVersion, err := version.NewVersion(semanticVersion)
		if err != nil {
			return "", err
		}
		return newVersion.String(), nil
	}
	return "", errors.New("invalid version string")
}
func parseSemanticVersion(version string) string {
	re := regexp.MustCompile(`([0-9]+\.){1,2}[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)*`)
	matches := re.FindAllString(version, -1)
	if matches != nil {
		if len(matches) > 1 {
			// 大于1 不管 只返回0
			return matches[0]
		}
		return matches[0]
	}
	return ""
}
