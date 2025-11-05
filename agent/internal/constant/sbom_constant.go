package constant

// SkipDir 需要跳过检测的目录
var SkipDir = []string{".idea", ".git", ".hg", ".svn", ".vscode"}

// NetWork 网络环境是否通畅
var NetWork bool

// JavaMaven 默认的javaMaven下载地址
const JavaMaven = "https://maven.aliyun.com/repository/public/"

type LanguageType string

const (
	UnknownLanguage LanguageType = ""
	Java            LanguageType = "Java"
	JavaScript      LanguageType = "JavaScript"
	Python          LanguageType = "Python"
	Golang          LanguageType = "Golang"
	Rust            LanguageType = "Rust"
	// Erlang 目前这些在 https://deps.dev/ 上面没有数据

	Erlang LanguageType = "Erlang"
	Php    LanguageType = "Php"
	Ruby   LanguageType = "Ruby"
)

func (l LanguageType) String() string {
	switch l {
	case Java:
		return "java"
	case JavaScript:
		return "java"
	case Python:
		return "python"
	case Golang:
		return "golang"
	case Rust:
		return "rust"
	case Erlang:
		return "erlang"
	case Php:
		return "php"
	case Ruby:
		return "ruby"
	case UnknownLanguage:
		return ""
	}
	return ""
}

const (
	BOMFormat = "MSEC"
)
