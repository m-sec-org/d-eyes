package utils

type Autorun struct {
	Type         string `json:"type"`
	Location     string `json:"location"`
	ImagePath    string `json:"image_path"`
	ImageName    string `json:"image_name"`
	Arguments    string `json:"arguments"`
	MD5          string `json:"md5"`
	SHA1         string `json:"sha1"`
	SHA256       string `json:"sha256"`
	Entry        string `json:"entry"`
	LaunchString string `json:"launch_string"`
}

func Autoruns() []*Autorun {
	return getAutoruns()
}
