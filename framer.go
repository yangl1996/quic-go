package quic

import (
	"sync"
	"os"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"container/heap"
)

type framer interface {
	HasData() bool

	QueueControlFrame(wire.Frame)
	AppendControlFrames([]ackhandler.Frame, protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount)

	AddActiveStream(protocol.StreamID)
	AppendStreamFrames([]ackhandler.Frame, protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount)
}

type streamRef struct {
	id protocol.StreamID
	epoch int
	index int
}

type streamQueue []*streamRef

func (pq streamQueue) Len() int { return len(pq) }

func (pq streamQueue) Less(i, j int) bool {
	return pq[i].epoch < pq[j].epoch
}

func (pq *streamQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*streamRef)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *streamQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n - 1]
	old[n - 1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}

func (pq streamQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

type framerI struct {
	mutex sync.Mutex

	streamGetter streamGetter
	version      protocol.VersionNumber

	activeStreams map[protocol.StreamID]struct{}
	streamQueue  streamQueue
	streamFifo []protocol.StreamID
	strictPrio bool

	controlFrameMutex sync.Mutex
	controlFrames     []wire.Frame

}

var _ framer = &framerI{}

func newFramer(
	strictPrio bool,
	streamGetter streamGetter,
	v protocol.VersionNumber,
) framer {
	return &framerI{
		streamGetter:  streamGetter,
		activeStreams: make(map[protocol.StreamID]struct{}),
		version:       v,
		strictPrio: strictPrio,
	}
}

func (f *framerI) HasData() bool {
	f.mutex.Lock()
	var hasData bool
	if f.strictPrio {
		hasData = len(f.streamQueue) > 0
	} else {
		hasData = len(f.streamFifo) > 0
	}
	f.mutex.Unlock()
	if hasData {
		return true
	}
	f.controlFrameMutex.Lock()
	hasData = len(f.controlFrames) > 0
	f.controlFrameMutex.Unlock()
	return hasData
}

func (f *framerI) QueueControlFrame(frame wire.Frame) {
	f.controlFrameMutex.Lock()
	f.controlFrames = append(f.controlFrames, frame)
	f.controlFrameMutex.Unlock()
}

func (f *framerI) AppendControlFrames(frames []ackhandler.Frame, maxLen protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount) {
	var length protocol.ByteCount
	f.controlFrameMutex.Lock()
	for len(f.controlFrames) > 0 {
		frame := f.controlFrames[len(f.controlFrames)-1]
		frameLen := frame.Length(f.version)
		if length+frameLen > maxLen {
			break
		}
		frames = append(frames, ackhandler.Frame{Frame: frame})
		length += frameLen
		f.controlFrames = f.controlFrames[:len(f.controlFrames)-1]
	}
	f.controlFrameMutex.Unlock()
	return frames, length
}

func (f *framerI) AddActiveStream(id protocol.StreamID) {
	f.mutex.Lock()
	if f.strictPrio {
		str, err := f.streamGetter.GetOrOpenSendStream(id)
		// The stream can be nil if it completed after it said it had data.
		if str == nil || err != nil {
			os.Exit(99)
			return // TODO
		}
		if _, ok := f.activeStreams[id]; !ok {
			heap.Push(&f.streamQueue, &streamRef{id, str.weight(), 0})
			f.activeStreams[id] = struct{}{}
		}
	} else {
		if _, ok := f.activeStreams[id]; !ok {
			f.streamFifo = append(f.streamFifo, id)
			f.activeStreams[id] = struct{}{}
		}
	}
	f.mutex.Unlock()
}

func (f *framerI) AppendStreamFrames(frames []ackhandler.Frame, maxLen protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount) {
	var length protocol.ByteCount
	var lastFrame *ackhandler.Frame
	f.mutex.Lock()
	// pop STREAM frames, until less than MinStreamFrameSize bytes are left in the packet
	var numActiveStreams int
	if f.strictPrio {
		numActiveStreams = len(f.streamQueue)
	} else {
		numActiveStreams = len(f.streamFifo)
	}
	for i := 0; i < numActiveStreams; i++ {
		if protocol.MinStreamFrameSize+length > maxLen {
			break
		}
		var id protocol.StreamID
		var ref *streamRef
		if f.strictPrio {
			ref = heap.Pop(&f.streamQueue).(*streamRef)
			id = ref.id
		} else {
			id = f.streamFifo[0]
			f.streamFifo = f.streamFifo[1:]
		}
		// This should never return an error. Better check it anyway.
		// The stream will only be in the streamQueue, if it enqueued itself there.
		str, err := f.streamGetter.GetOrOpenSendStream(id)
		// The stream can be nil if it completed after it said it had data.
		if str == nil || err != nil {
			delete(f.activeStreams, id)
			continue
		}
		remainingLen := maxLen - length
		// For the last STREAM frame, we'll remove the DataLen field later.
		// Therefore, we can pretend to have more bytes available when popping
		// the STREAM frame (which will always have the DataLen set).
		remainingLen += utils.VarIntLen(uint64(remainingLen))
		frame, hasMoreData := str.popStreamFrame(remainingLen)
		if hasMoreData { // put the stream back in the queue (at the end)
			if f.strictPrio {
				heap.Push(&f.streamQueue, ref)
			} else {
				f.streamFifo = append(f.streamFifo, id)
			}
		} else { // no more data to send. Stream is not active any more
			delete(f.activeStreams, id)
		}
		// The frame can be nil
		// * if the receiveStream was canceled after it said it had data
		// * the remaining size doesn't allow us to add another STREAM frame
		if frame == nil {
			continue
		}
		frames = append(frames, *frame)
		length += frame.Length(f.version)
		lastFrame = frame
	}
	f.mutex.Unlock()
	if lastFrame != nil {
		lastFrameLen := lastFrame.Length(f.version)
		// account for the smaller size of the last STREAM frame
		lastFrame.Frame.(*wire.StreamFrame).DataLenPresent = false
		length += lastFrame.Length(f.version) - lastFrameLen
	}
	return frames, length
}
