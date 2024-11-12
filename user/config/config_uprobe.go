package config

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

type UprobeConfig struct {
	BaseConfig
	EbpfFileName  string         `json:"ebpf_file_name"`
	EbpfProgSpecs []EbpfProgSpec `json:"ebpf_prog_specs"`
	EbpfMapSpecs  []EbpfMapSpec  `json:"ebpf_map_specs"`
}

func NewUprobeConfig() *UprobeConfig {
	config := &UprobeConfig{}
	config.PerCpuMapSize = DefaultMapSizePerCpu
	return config
}

func (conf *UprobeConfig) Check() error {

	for _, spec := range conf.EbpfProgSpecs {
		if spec.BinaryPath == "" || len(strings.TrimSpace(spec.BinaryPath)) <= 0 {
			return errors.New("Uprobe binary path cant be null.")
		}

		_, e := os.Stat(spec.BinaryPath)
		if e != nil {
			return e
		}
	}

	return nil
}

func (conf *UprobeConfig) Bytes() []byte {
	b, e := json.Marshal(conf)
	if e != nil {
		return []byte{}
	}
	return b
}
