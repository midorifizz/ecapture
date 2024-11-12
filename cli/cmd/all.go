package cmd

import (
	"fmt"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/module"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
	"path/filepath"
)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "all probe start",
	Long:  "run all eBPF probe",
	Run:   allCommandFunc,
}

func init() {
	rootCmd.AddCommand(allCmd)
}

func allCommandFunc(command *cobra.Command, args []string) {
	var logger = initGlobalLogger(globalConf.LoggerAddr, globalConf)
	modConfigMaps, err := loadAllProbeConfigs("probes", &logger)
	if err != nil {
		logger.Error().Err(err).Msg("load all probe configs failed.")
		return
	}
	runAllModule(modConfigMaps, logger)
}

// 定义 probe.yaml 中的结构
type ProbeYAML struct {
	Progs []Prog `yaml:"progs"`
	Maps  []Map  `yaml:"maps"`
}

type Prog struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	Section    string `yaml:"section"`
	AttachTo   string `yaml:"attach_to"`
	BinaryPath string `yaml:"binary_path"`
}

type Map struct {
	Name   string  `yaml:"name"`
	Fields []Field `yaml:"fields"`
}

type Field struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	Size int    `yaml:"size,omitempty"`
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
	return "mysqld_kern_noncore_less52.o", nil
}

// loadProbeConfig 读取和解析 probe.yaml 文件
func loadProbeConfig(probeDir string, logger *zerolog.Logger) (*config.UprobeConfig, error) {
	// 解析 probe.yaml 文件
	logger.Info().Str("probeDir", probeDir).Msg("start load probe config")
	yamlPath := filepath.Join(probeDir, "probe.yaml")
	data, err := ioutil.ReadFile(yamlPath)
	uprobeConfig := config.NewUprobeConfig()

	if err != nil {
		return uprobeConfig, fmt.Errorf("failed to read file: %w", err)
	}

	var probeYAML ProbeYAML
	if err := yaml.Unmarshal(data, &probeYAML); err != nil {
		return uprobeConfig, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// 查找 .o 文件并填充到 EbpfFileName
	ebpfFileName, err := findEbpfObjectFile(probeDir)
	if err != nil {
		return uprobeConfig, err
	}

	// 创建 UprobeConfig 实例
	uprobeConfig.EbpfFileName = ebpfFileName
	uprobeConfig.EbpfProgSpecs = []config.EbpfProgSpec{}
	uprobeConfig.EbpfMapSpecs = []config.EbpfMapSpec{}

	// 解析 progs 部分
	for _, prog := range probeYAML.Progs {
		uprobeConfig.EbpfProgSpecs = append(uprobeConfig.EbpfProgSpecs, config.EbpfProgSpec{
			Section:      prog.Section,
			EbpfFuncName: prog.Name,
			AttachTo:     prog.AttachTo,
			BinaryPath:   prog.BinaryPath,
		})
		logger.Info().Str("EbpfFileName", ebpfFileName).
			Str("Section", prog.Section).
			Str("EbpfFuncName", prog.Name).
			Str("AttachTo", prog.AttachTo).
			Str("BinaryPath", prog.BinaryPath).Msg("EbpfProgSpecs init finish.")
	}

	// 解析 maps 部分
	for _, m := range probeYAML.Maps {
		mapFields := []config.MapField{}
		for _, field := range m.Fields {
			mapFields = append(mapFields, config.MapField{
				Name: field.Name,
				Type: field.Type,
				Size: field.Size,
			})
		}

		uprobeConfig.EbpfMapSpecs = append(uprobeConfig.EbpfMapSpecs, config.EbpfMapSpec{
			Name:   m.Name,
			Fields: mapFields,
		})
		logger.Info().Str("EbpfFileName", ebpfFileName).
			Str("MapName", m.Name).
			Msg("EbpfMapSpecs init finish")
	}

	return uprobeConfig, nil
}

// loadAllProbeConfigs 遍历 probes 目录并加载每个子目录的 probe.yaml 文件
func loadAllProbeConfigs(probesDir string, logger *zerolog.Logger) (map[string]config.IConfig, error) {
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
				// 注册 Uprobe Module 初始化方法
				module.RegisteFunc(info.Name(), module.NewUprobe)
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking probes directory: %w", err)
	}

	return modConfigMaps, nil
}
