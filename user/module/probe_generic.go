package module

import (
	"bytes"
	"context"
	"fmt"
	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/user/config"
	"github.com/gojue/ecapture/user/event"
	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
	"io"
	"math"
)

type GenericProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventMaps         []*ebpf.Map
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
}

// 对象初始化
func (m *GenericProbe) Init(ctx context.Context, logger *zerolog.Logger, conf config.IConfig, ecw io.Writer) error {
	err := m.Module.Init(ctx, logger, conf, ecw)
	if err != nil {
		return err
	}
	m.conf = conf
	m.Module.SetChild(m)
	m.eventMaps = make([]*ebpf.Map, 0)
	m.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	return nil
}

func (m *GenericProbe) Start() error {
	if err := m.start(); err != nil {
		return err
	}
	return nil
}

func (m *GenericProbe) start() error {

	// fetch ebpf assets
	var bpfFileName = m.geteBPFName(m.conf.(*config.GenericProbeConfig).EbpfFileName)
	m.logger.Info().Str("bpfFileName", bpfFileName).Msg("BPF bytecode file is matched.")

	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		m.logger.Error().Err(err).Strs("bytecode files", assets.AssetNames()).Msg("couldn't find bpf bytecode file")
		return fmt.Errorf("couldn't find asset %v.", err)
	}

	// setup the managers
	err = m.setupManagers()
	if err != nil {
		return fmt.Errorf("%s module couldn't find binPath %v.", m.Name(), err)
	}

	// initialize the bootstrap manager
	if err = m.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), m.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// start the bootstrap manager
	if err = m.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v", err)
	}

	// 加载map信息，map对应events decode表。
	err = m.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (m *GenericProbe) Close() error {
	if err := m.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v.", err)
	}
	return m.Module.Close()
}

func (m *GenericProbe) setupManagers() error {
	progSpecs := m.conf.(*config.GenericProbeConfig).EbpfProgSpecs
	mapSpecs := m.conf.(*config.GenericProbeConfig).EbpfMapSpecs

	var probes []*manager.Probe
	var maps []*manager.Map
	// 设置 manager probe
	for _, pspec := range progSpecs {
		var probe *manager.Probe
		switch pspec.Type {
		case "kprobe", "kretprobe":
			probe = &manager.Probe{
				Section:          pspec.Section,
				EbpfFuncName:     pspec.EbpfFuncName,
				AttachToFuncName: pspec.AttachTo,
			}
		case "uprobe", "uretprobe":
			probe = &manager.Probe{
				Section:          pspec.Section,
				EbpfFuncName:     pspec.EbpfFuncName,
				AttachToFuncName: pspec.AttachTo,
				UAddress:         pspec.AttachOffset,
				BinaryPath:       pspec.BinaryPath,
			}
		default:
			return fmt.Errorf("setup mangaers failed, not support ebpf program type: %s", pspec.Type)
		}

		probes = append(probes, probe)
		m.logger.Info().Str("ebpfFileName", m.conf.(*config.GenericProbeConfig).EbpfFileName).
			Interface("probe", probe).
			//Str("type", pspec.Type).
			//Str("section", pspec.Section).
			//Str("attachTo", pspec.AttachTo).
			//Str("ebpfFuncName", pspec.EbpfFuncName).
			//Str("binaryPath", pspec.BinaryPath).
			//Uint64("uprobeOffset", pspec.AttachOffset).
			Msg("GenericProbe eBPF prog setup")
	}

	// 设置 manager map
	for _, mspec := range mapSpecs {
		ebpfMap := &manager.Map{
			Name: mspec.Name,
		}
		maps = append(maps, ebpfMap)
		m.logger.Info().Str("ebpfFileName", m.conf.(*config.GenericProbeConfig).EbpfFileName).
			Str("mapName", mspec.Name).
			Msg("GenericProbe eBPF map setup")
	}

	m.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}

	m.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
	return nil
}

func (m *GenericProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := m.eventFuncMaps[em]
	return fun, found
}

func (m *GenericProbe) initDecodeFun() error {
	mapSpecs := m.conf.(*config.GenericProbeConfig).EbpfMapSpecs
	for _, mspec := range mapSpecs {
		bm, found, err := m.bpfManager.GetMap(mspec.Name)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("cannot found map: %s", mspec.Name)
		}
		m.eventMaps = append(m.eventMaps, bm)
		m.eventFuncMaps[bm] = &event.GenericEvent{}
	}

	return nil
}

func (m *GenericProbe) Events() []*ebpf.Map {
	return m.eventMaps
}

func NewGenericProbe(name string) IModule {
	mod := &GenericProbe{}
	mod.name = name
	return mod
}
