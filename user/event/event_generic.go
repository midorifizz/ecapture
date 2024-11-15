package event

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gojue/ecapture/user/config"
	"strings"
)

type GenericEvent struct {
	eventType EventType
	Pid       uint32                 `json:"pid"`
	Uid       uint32                 `json:"uid"`
	Len       uint64                 `json:"len"`
	Comm      [16]byte               `json:"comm"`
	DataMap   map[string]interface{} `json:"data_map"`
	DataBytes []byte                 `json:"data_bytes"`
}

func (event *GenericEvent) Decode(payload []byte, conf config.IConfig) (err error) {
	buf := bytes.NewBuffer(payload)
	specs := conf.(*config.GenericProbeConfig).EbpfMapSpecs

	for _, spec := range specs {
		for _, field := range spec.Fields {
			switch field.Type {
			case "uint64":
				var value uint64
				if err = binary.Read(buf, binary.LittleEndian, &value); err != nil {
					return err
				}
				event.DataMap[field.Name] = value
			case "int8":
				var value int8
				if err = binary.Read(buf, binary.LittleEndian, &value); err != nil {
					return err
				}
				event.DataMap[field.Name] = value
			case "uint32":
				var value uint32
				if err = binary.Read(buf, binary.LittleEndian, &value); err != nil {
					return err
				}
				event.DataMap[field.Name] = value
			case "byte_array":
				array := make([]byte, field.Size)
				if err = binary.Read(buf, binary.LittleEndian, &array); err != nil {
					return err
				}
				event.DataMap[field.Name] = strings.TrimRight(string(array), "\x00")
			default:
				return fmt.Errorf("unsupported type: %s", field.Type)
			}
		}
	}
	dataBytes, err := json.Marshal(event.DataMap)
	if err != nil {
		return err
	}
	event.DataBytes = dataBytes
	return nil
}

func (event *GenericEvent) String() string {
	return string(event.DataBytes)
}

func (event *GenericEvent) StringHex() string {
	return hex.EncodeToString(event.DataBytes)
}

func (event *GenericEvent) Clone() IEventStruct {
	evt := new(GenericEvent)
	evt.eventType = EventTypeOutput
	evt.DataMap = make(map[string]interface{})
	return evt
}

func (event *GenericEvent) EventType() EventType {
	return event.eventType
}

func (event *GenericEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s", event.Pid, event.Uid, event.Comm)
}

func (event *GenericEvent) Payload() []byte {
	return event.DataBytes[:]
}

func (event *GenericEvent) PayloadLen() int {
	return int(event.Len)
}
