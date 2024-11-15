package config

import (
	"encoding/json"
	"errors"
	"fmt"
	manager "github.com/gojue/ebpfmanager"
	"os"
	"regexp"
	"strings"
)

type MapField struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int    `json:"size"` // 对于字节数组，定义其大小
}

type EbpfProgSpec struct {
	Section         string `json:"section"`
	Type            string `json:"type"`
	EbpfFuncName    string `json:"ebpf_func_name"`
	AttachFunc      string `json:"attach_func"`
	AttachMatchFunc string `json:"attach_match_func"`
	AttachOffset    uint64 `json:"attach_offset"`
	AttachTo        string `json:"attach_to"`
	BinaryPath      string `json:"binary_path"`
}

type EbpfMapSpec struct {
	Name   string     `json:"name"`
	Fields []MapField `json:"fields"`
}

type GenericProbeConfig struct {
	BaseConfig
	EbpfFileName  string         `json:"ebpf_file_name"`
	EbpfProgSpecs []EbpfProgSpec `json:"ebpf_prog_specs"`
	EbpfMapSpecs  []EbpfMapSpec  `json:"ebpf_map_specs"`
}

func NewGenericProbeConfig() *GenericProbeConfig {
	config := &GenericProbeConfig{}
	config.PerCpuMapSize = DefaultMapSizePerCpu
	return config
}

func (conf *GenericProbeConfig) Check() error {

	for idx, spec := range conf.EbpfProgSpecs {
		switch spec.Type {
		case "kprobe", "kretprobe":
			if err := conf.checkKprobe(idx, spec); err != nil {
				return err
			}
		case "uprobe", "uretprobe":
			if err := conf.checkUprobe(idx, spec); err != nil {
				return err
			}
		default:
			return fmt.Errorf("not support ebpf program type: %s", spec.Type)
		}
	}

	return nil
}

func (conf *GenericProbeConfig) checkKprobe(idx int, spec EbpfProgSpec) error {
	if spec.AttachFunc == "" {
		return errors.New("kprobe probe yaml attach_func cannot be null")
	}

	conf.EbpfProgSpecs[idx].AttachTo = spec.AttachFunc
	return nil
}

func (conf *GenericProbeConfig) checkUprobe(idx int, spec EbpfProgSpec) error {
	// 检查程序二进制文件是否存在
	if spec.BinaryPath == "" || len(strings.TrimSpace(spec.BinaryPath)) <= 0 {
		return errors.New("uprobe binary path cant be null")
	}

	_, e := os.Stat(spec.BinaryPath)
	if e != nil {
		return e
	}

	// 如果配置 Offset ，则使用用户指定的 Offset
	if spec.AttachOffset != 0 {
		conf.EbpfProgSpecs[idx].AttachTo = "[_IGNORE_]"
		return nil
	}

	// 找到与提供的 pattern 匹配的第一个符号的 Offset
	var funcPattern string
	if len(spec.AttachMatchFunc) > 0 {
		funcPattern = spec.AttachMatchFunc
	} else {
		funcPattern = fmt.Sprintf("^%s$", spec.AttachFunc)
	}
	pattern, err := regexp.Compile(funcPattern)
	if err != nil {
		return fmt.Errorf("failed to compile pattern %s: %w", funcPattern, err)
	}

	// 检索动态符号偏移量
	offsets, err := manager.FindSymbolOffsets(spec.BinaryPath, pattern)
	if err != nil {
		return fmt.Errorf("couldn't find symbol matching %s in %s: %w", pattern.String(), spec.BinaryPath, err)
	}

	conf.EbpfProgSpecs[idx].AttachTo = offsets[0].Name
	conf.EbpfProgSpecs[idx].AttachOffset = offsets[0].Value
	return nil
}

func (conf *GenericProbeConfig) Bytes() []byte {
	b, e := json.Marshal(conf)
	if e != nil {
		return []byte{}
	}
	return b
}
