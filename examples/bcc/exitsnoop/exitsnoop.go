package main

import (
    "log"
//    "time"
	"fmt"
	"os"
	"os/signal"
	"encoding/binary"
	"bytes"
    "flag"
	"unsafe"
    "strings"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

var code = `
#include <linux/sched.h>

struct data_t {
    u64 start_time;
    u64 exit_time;
    u32 pid;
    u32 tid;
    u32 ppid;
    int exit_code;
    u32 sig_info;
    char task[TASK_COMM_LEN];
} __attribute__((packed));

//#ifndef BPF_STATIC_ASSERT
//#define BPF_STATIC_ASSERT(condition) __attribute__((unused)) \
//    extern int bpf_static_assert[(condition) ? 1 : -1]
//#endif

//BPF_STATIC_ASSERT(sizeof(struct data_t) == CTYPES_SIZEOF_DATA);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    //if (FILTER_PID || FILTER_EXIT_CODE) { return 0; }

    struct data_t data = {
        .start_time = task->start_time,
        .exit_time = bpf_ktime_get_ns(),
        .pid = task->tgid,
        .tid = task->pid,
        .ppid = task->parent->tgid,
        .exit_code = task->exit_code >> 8,
        .sig_info = task->exit_code & 0xFF,
    };
    bpf_get_current_comm(&data.task, sizeof(data.task));

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
`
type exitEvent struct {
    Start_time      uint64
    Exit_time       uint64
    Pid             uint32
    Tid             uint32
    Ppid            uint32
    Exit_code       int32
    Sig_info        uint32
    Task            [16]byte
}

func main() {
	filterComm := flag.String("n", "", `only print command lines containing a name, for example "main"`)

    flag.Parse()

    m := bpf.NewModule(code, []string{})
    //log.Printf("%#v", m)

    target, err := m.LoadTracepoint("tracepoint__sched__sched_process_exit")
    //_, err := m.LoadTracepoint("tracepoint__sched__sched_process_exit")
    if err != nil {
        log.Fatalf("Failed to load tracepoint: %s", err)
    }

    err = m.AttachTracepoint("sched:sched_process_exit", target)
    if err != nil {
        log.Fatalf("Failed to attach tracepoint: %s", err)
    }

    table := bpf.NewTable(m.TableId("events"), m)

	channel := make(chan []byte, 1000)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
        for {
            data := <-channel

            var event exitEvent
			err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)

            if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			} else {
				comm := C.GoString((*C.char)(unsafe.Pointer(&event.Task)))
				if *filterComm != "" && !strings.Contains(comm, *filterComm) {
					continue
				}

                fmt.Printf("%v\n", event)
            }
        } // for
    }()


	perfMap.Start()
	<-sig
	perfMap.Stop()


//    time.Sleep(time.Hour)
}


