module github.com/m-sec-org/d-eyes/agent

go 1.24.0

require (
	github.com/cilium/ebpf v0.20.0
	github.com/fatih/color v1.17.0
	github.com/m-sec-org/d-eyes/server v0.0.0
	github.com/pkg/errors v0.9.1
	github.com/shirou/gopsutil/v4 v4.24.5
	github.com/stretchr/testify v1.9.0
	github.com/urfave/cli/v2 v2.27.2
	golang.org/x/term v0.36.0
	google.golang.org/grpc v1.76.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250804133106-a7a43d27e69b // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

require (
	github.com/CycloneDX/cyclonedx-go v0.9.0
	github.com/axgle/mahonia v0.0.0-20180208002826-3358181d7394
	github.com/botherder/go-files v0.0.0-20180205213231-2246e61e05ec
	github.com/cpuguy83/go-md2man/v2 v2.0.6 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-version v1.7.0
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/mattn/go-shellwords v1.0.12
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/olekukonko/tablewriter v0.0.5
	github.com/package-url/packageurl-go v0.1.3
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/richardlehane/mscfb v1.0.4 // indirect
	github.com/richardlehane/msoleps v1.0.3 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/toolkits/slice v0.0.0-20141116085117-e44a80af2484
	github.com/xrash/smetrics v0.0.0-20240312152122-5f08fbb34913 // indirect
	github.com/xuri/efp v0.0.0-20231025114914-d1ff6096ae53 // indirect
	github.com/xuri/excelize/v2 v2.8.1
	github.com/xuri/nfp v0.0.0-20230919160717-d98342af3f05 // indirect
	github.com/yusufpapurcu/wmi v1.2.4
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/net v0.46.0
	golang.org/x/sys v0.37.0
	golang.org/x/text v0.30.0 // indirect
)

replace github.com/m-sec-org/d-eyes/server => ../server
