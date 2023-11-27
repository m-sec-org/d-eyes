package plugins

import (
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gookit/color"
	"github.com/olekukonko/tablewriter"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/urfave/cli/v2"

	"d-eyes/cmd"
)

type PluginNetstat struct {
	NtiToken string
}

func init() {
	cmd.Register(new(PluginNetstat).InitCommands())
}

func (p *PluginNetstat) InitCommands() *cli.Command {
	return &cli.Command{
		Name:   "netstat",
		Usage:  "Command for displaying host network information",
		Action: p.Run,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "token",
				Aliases:     []string{"t"},
				Usage:       "nti token",
				Destination: &p.NtiToken,
			},
		},
	}
}

func (p *PluginNetstat) Run(c *cli.Context) error {
	networkData := make([][]string, 0)
	var remoteIp []string
	ps, err := process.Processes()
	if err != nil {
		return err
	}

	log.Println("共", len(ps), "个进程, 获取其网络连接详情")
	pid := os.Getpid()
	for i := range ps {
		if pid == int(ps[i].Pid) || ps[i].Pid == 0 {
			continue
		}
		name, err := ps[i].Name()
		if err != nil {
			continue
		}
		fmt.Print("\r正在获取 (", i, "/", len(ps), ") pid:", ps[i].Pid, "[", name, "]                                                          ")

		connList := make([]string, 0)
		connection := make([]string, 0)
		_pc, _ := ps[i].Connections()
		for _, conn := range _pc {
			c := fmt.Sprintf(
				"%v:%v<->%v:%v(%v)\n",
				conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port, conn.Status,
			)
			if ipFilter(conn.Raddr.IP) {
				remoteIp = append(remoteIp, conn.Raddr.IP)
			}
			connection = append(connection, c)
		}
		_pUname, _ := ps[i].Username()
		if len(connection) > 0 && _pUname != "" {
			network := strings.Join(connection, "")
			_exe, _ := ps[i].Exe()
			path := StringNewLine(_exe, 25)
			username, _ := ps[i].Username()
			connList = append(connList, fmt.Sprintf("%v", ps[i].Pid), fmt.Sprintf("%v", username), network, path)
			networkData = append(networkData, connList)
		}
	}
	color.Greenp("\r==============================================================================================\n")

	tableConn := tablewriter.NewWriter(os.Stdout)
	tableConn.SetHeader([]string{"pid", "user", "local/remote(TCP Status)", "program name"})
	tableConn.SetBorder(true)
	tableConn.SetRowLine(true)
	tableConn.AppendBulk(networkData)
	tableConn.Render()
	remoteIpNew := RemoveRepeatedElement(remoteIp)

	if len(remoteIpNew) > 0 {
		if p.NtiToken != "" {
			client := resty.New()
			var ntiResp NtiResp
			for i := range remoteIpNew {
				_, _ = client.R().
					SetQueryParam("query", remoteIpNew[i]).
					SetHeader("X-Ns-Nti-Key", p.NtiToken).
					SetHeader("Accept", "application/nsfocus.nti.spec+json; version=2.0").
					SetResult(&ntiResp).
					Get("https://nti.nsfocus.com/api/v2/objects/ioc-ipv4/")
				color.Greenp("==============================================================================================\n")
				color.Greenp("* [", remoteIpNew[i], "] NTI检测结果:\n")
				fmt.Printf("%+v\n", ntiResp)
			}
		}

		f, err := os.Create("RemoteConnectionIP.csv")
		if err != nil {
			return err
		}
		_, err = f.WriteString("\xEF\xBB\xBF")
		if err != nil {
			return err
		}
		writer := csv.NewWriter(f)
		length := len(remoteIpNew)
		for i := 0; i < length; i++ {
			err := writer.Write([]string{remoteIpNew[i]})
			if err != nil {
				return err
			}
		}
		writer.Flush()
		f.Close()
		fmt.Println("The IP of the local remote connection has been exported to 'RemoteConnectionIP.csv'.")
	} else {
		fmt.Println("\nThere is no remote connection IP on this host.")
	}
	return nil
}

var ipCache = make(map[string]struct{})

// 过滤ipv6 内网ip地址 本地ip地址
func ipFilter(ip string) bool {
	parsedIP := net.ParseIP(ip)

	// check if it's an IPv4 address
	if parsedIP == nil || parsedIP.To4() == nil {
		return false
	}

	if parsedIP.IsPrivate() || !parsedIP.IsGlobalUnicast() || parsedIP.IsLoopback() {
		return false
	}

	ipCache[ip] = struct{}{}
	return true
}

func RemoveRepeatedElement(arr []string) (newArr []string) {
	newArr = make([]string, 0)
	for i := 0; i < len(arr); i++ {
		if arr[i] == "127.0.0.1" || arr[i] == "0.0.0.0" || arr[i] == "::" || arr[i] == "::1" || arr[i] == "" {
			continue
		}
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return
}

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

type NtiResp struct {
	Count       int       `json:"count"`
	SpecVersion string    `json:"spec_version"`
	Objects     []Objects `json:"objects"`
	Type        string    `json:"type"`
}
type Tags struct {
	TagValues []string `json:"tag_values"`
	TagType   string   `json:"tag_type"`
}
type Observables struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type Objects struct {
	ValidUntil  time.Time     `json:"valid_until"`  // 有效期截止时间
	Confidence  int           `json:"confidence"`   // 情报置信度，0-100 的整形数，值越大置信度越高
	ThreatLevel int           `json:"threat_level"` // 威胁程度，低到高（1,3,5），其中 1(低)，3（中），5（高）。
	Revoked     bool          `json:"revoked"`
	Tags        []Tags        `json:"tags"` // Ioc出站/入站标记
	CreditLevel int           `json:"credit_level"`
	Pattern     string        `json:"pattern"`  // 指示器模式。带与或条件的规则表达式，条件以可观察对象字段值的方式表示。
	Modified    time.Time     `json:"modified"` // 情报更新时间
	CreatedBy   string        `json:"created_by"`
	Observables []Observables `json:"observables"`  // 可观察数据值，解释该指示器对应的ip/域名/url/样本。
	ThreatTypes []int         `json:"threat_types"` // 威胁类型列表。
	ActTypes    []int         `json:"act_types"`    // 处置类型：  0：产品可根据策略正常处置，为默认值  1：监测  2：拦截  3：回溯分析  4：应急响应  5：热点事件
	Type        string        `json:"type"`
	ID          string        `json:"id"`
	Categories  []string      `json:"categories"` // 指示器类型：  ip：恶意ip   c2：c2主机
}
