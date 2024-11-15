package cmd

import (
	"github.com/gojue/ecapture/user/module"
	"github.com/spf13/cobra"
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
	modConfigMaps, err := module.LoadAllProbeConfigs("probes", &logger)
	if err != nil {
		logger.Error().Err(err).Msg("load all probe configs failed.")
		return
	}
	runAllModule(modConfigMaps, logger)
}
