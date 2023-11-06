package utils

func StringNewLine(str string, ln uint8) string {
	var sub_str string
	res_str := ""
	for {
		if len(str) < int(ln) {
			res_str += str
			break
		}
		sub_str = str[0:ln]
		str = str[ln:]
		res_str += sub_str + "\n"
	}
	return res_str
}
