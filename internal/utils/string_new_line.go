package utils

func StringNewLine(str string, ln uint8) string {
	var subStr string
	resStr := ""
	for {
		if len(str) < int(ln) {
			resStr += str
			break
		}
		subStr = str[0:ln]
		str = str[ln:]
		resStr += subStr + "\n"
	}
	return resStr
}
