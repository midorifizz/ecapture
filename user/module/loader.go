package module

import (
	"fmt"
	"github.com/gojue/ecapture/user/config"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
	"path/filepath"
)

// ProbeYAML 定义 probe.yaml 中的结构
type ProbeYAML struct {
	Progs []Prog `yaml:"progs"`
	Maps  []Map  `yaml:"maps"`
}

type Prog struct {
	Name            string `yaml:"name"`
	Type            string `yaml:"type"`
	Section         string `yaml:"section"`
	AttachFunc      string `yaml:"attach_func"`
	AttachMatchFunc string `yaml:"attach_match_func"`
	AttachOffset    uint64 `yaml:"attach_offset"`
	BinaryPath      string `yaml:"binary_path"`
}

type Map struct {
	Name   string  `yaml:"name"`
	Fields []Field `yaml:"fields"`
}

type Field struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	Size int    `yaml:"size"`
}

// findEbpfObjectFile 查找目录中 .o 结尾的文件
func findEbpfObjectFile(probeDir string) (string, error) {
	//files, err := ioutil.ReadDir(probeDir)
	//if err != nil {
	//	return "", fmt.Errorf("failed to read directory: %w", err)
	//}
	//
	//for _, file := range files {
	//	if !file.IsDir() && strings.HasSuffix(file.Name(), ".o") {
	//		return filepath.Join(probeDir, file.Name()), nil
	//	}
	//}
	//
	//return "", fmt.Errorf("no .o file found in directory: %s", probeDir)
	log.Info().Str("probeDir", probeDir).Msg("findEbpfObjectFile")
	dirName := filepath.Base(probeDir)
	if dirName == "mysql" {
		return "user/bytecode/mysqld_kern.o", nil
	} else {
		return "user/bytecode/openfile_kern.o", nil
	}
}

func createGenericProbeConfig(ebpfFileName string, probeYAML ProbeYAML, logger *zerolog.Logger) *config.GenericProbeConfig {
	// 创建 GenericProbeConfig 实例
	probeConfig := config.NewGenericProbeConfig()
	probeConfig.EbpfFileName = ebpfFileName
	probeConfig.EbpfProgSpecs = []config.EbpfProgSpec{}
	probeConfig.EbpfMapSpecs = []config.EbpfMapSpec{}

	// 解析 progs 部分
	for _, prog := range probeYAML.Progs {
		eps := config.EbpfProgSpec{
			Section:         prog.Section,
			Type:            prog.Type,
			EbpfFuncName:    prog.Name,
			AttachFunc:      prog.AttachFunc,
			AttachMatchFunc: prog.AttachMatchFunc,
			AttachOffset:    prog.AttachOffset,
			BinaryPath:      prog.BinaryPath,
		}
		probeConfig.EbpfProgSpecs = append(probeConfig.EbpfProgSpecs, eps)
		logger.Info().Str("EbpfFileName", ebpfFileName).
			Interface("EbpfProgSpec", eps).
			Msg("EbpfProgSpec init finish.")
	}

	// 解析 maps 部分
	for _, m := range probeYAML.Maps {
		var mapFields []config.MapField
		for _, field := range m.Fields {
			mapFields = append(mapFields, config.MapField{
				Name: field.Name,
				Type: field.Type,
				Size: field.Size,
			})
		}

		ems := config.EbpfMapSpec{
			Name:   m.Name,
			Fields: mapFields,
		}
		probeConfig.EbpfMapSpecs = append(probeConfig.EbpfMapSpecs, ems)
		logger.Info().Str("EbpfFileName", ebpfFileName).
			Interface("EbpfMapSpecs", ems).
			Msg("EbpfMapSpecs init finish")
	}
	return probeConfig
}

// loadProbeConfig 读取和解析 probe.yaml 文件
func loadProbeConfig(probeDir string, logger *zerolog.Logger) (config.IConfig, error) {
	// 解析 probe.yaml 文件
	logger.Info().Str("probeDir", probeDir).Msg("start load probe config")
	yamlPath := filepath.Join(probeDir, "probe.yaml")
	data, err := ioutil.ReadFile(yamlPath)

	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var probeYAML ProbeYAML
	if err := yaml.Unmarshal(data, &probeYAML); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// 查找 .o 文件并填充到 EbpfFileName
	ebpfFileName, err := findEbpfObjectFile(probeDir)
	if err != nil {
		return nil, err
	}

	// 创建 probe 配置实例
	probeConfig := createGenericProbeConfig(ebpfFileName, probeYAML, logger)
	return probeConfig, nil
}

// LoadAllProbeConfigs 遍历 probes 目录并加载每个子目录的 probe.yaml 文件
func LoadAllProbeConfigs(probesDir string, logger *zerolog.Logger) (map[string]config.IConfig, error) {
	modConfigMaps := make(map[string]config.IConfig)

	err := filepath.Walk(probesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			// 检查子目录中是否存在 probe.yaml 文件
			yamlPath := filepath.Join(path, "probe.yaml")
			if _, err := os.Stat(yamlPath); err == nil {
				// 解析该目录的 probe.yaml
				conf, err := loadProbeConfig(path, logger)
				if err != nil {
					logger.Error().Err(err).Str("path", path).Msg("Error loading probe.yaml")
					return nil // 继续遍历其他目录
				}
				modConfigMaps[info.Name()] = conf
				// 注册 GenericProbe Module 初始化方法
				RegisteFunc(info.Name(), NewGenericProbe)
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking probes directory: %w", err)
	}

	return modConfigMaps, nil
}
